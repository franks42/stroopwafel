# Project Review: stroopwafel

**Reviewer:** inkling-2-mini
**Date:** November 21, 2026
**Scope:** Architecture, design and code review of the engine at v0.12.0
**Method:** Read-only review — source, tests, docs, build. Tests were not run; the 71-test count and 0.12.0 history are as documented in `context.md` and the README.

> **Superseded (2026-11-23)** by `docs/review-swival-inkling-2-mini.md`. Kept as the historical record; don't act on it. In particular, "no correctness bugs in the happy path" is wrong: the arity mismatch fails open for checks, rule bodies _and_ allow policies (an authorization bypass, not checks-only), and `graph` threw on every passing `evaluate` result. Both are fixed on branch `fix/strict-arity`; remaining work is tracked in `docs/TODO.md`.

---

## Overall

This is a well-designed, disciplined library. The 0.11.0 split into four layers
(engine / signet / stroopwafel-pdp / PEP) is the right call: the engine is pure,
zero-dependency, and trusts its input, with all crypto and trust decisions pushed
to the PDP. The fail-closed fixpoint limits (0.12.0) fix a real, reproduced
fail-open bug. Scope isolation via origin sets, the closed expression whitelist,
the `:when`/`:let` guard design, and the explain/graph tooling are all thoughtful.

This pass found **no correctness bugs in the happy path**, but one genuine
arity-mismatch gap in unification (findings below) and a few smaller items
worth acting on.

## What the project does

- **Library**: a pure Datalog engine for authorization decisions. Facts, rules,
  checks and policies go in; `{:valid? …}` comes out. RFC-style Datalog over
  plain vectors, with origin sets tracking which block a fact came from.
- **CLI**: none — by design. The engine is a library; the PEP is the caller.
- **Packaging**: JAR to Clojars (`com.github.franks42/stroopwafel`, v0.12.0) via
  tools.build. Runs on the JVM and babashka.
- **Consumers**: stroopwafel-pdp (SPKI/SDSI assertion pipeline), which verifies
  signatures and extracts facts before calling `evaluate`.

## Architecture

### The four-layer split

```
┌─────────────────────────────────────────────────────────┐
│  Application PEP (alpaca-clj, websocket-app, etc.)      │
│  Enforces decisions in the app's wire format             │
├─────────────────────────────────────────────────────────┤
│  stroopwafel-pdp                                         │
│  Verifies signed blocks, turns them into facts,          │
│  calls the engine; trust roots, replay protection         │
├──────────────────────┬──────────────────────────────────┤
│  signet              │  stroopwafel                      │
│  Crypto: keys,       │  Datalog engine                   │
│  signing, envelopes  │  Facts, rules, joins, decide      │
│  Depends on:         │  Depends on:                      │
│  cedn, uuidv7        │  NOTHING (zero deps)              │
└──────────────────────┴──────────────────────────────────┘
```

This is the single most important design decision in the project. The engine
knows nothing about crypto, envelopes, keys, or HTTP. The PDP is the trust
boundary: it verifies signatures and produces facts, and the engine trusts
them. The README and context.md both state this explicitly. Good separation,
and the engine's zero-dependency property is what makes it embeddable.

### The engine: `evaluate` → `eval-token`

The public entry point (`stroopwafel.core/evaluate`) does three things:

1. Extracts the logical content (`:facts`/`:rules`/`:checks`) from each block,
   dropping `:external-key` (used only for trust computation, not passed down).
2. Computes which third-party blocks are trusted by comparing `:external-key`
   bytes against the authorizer's `:trusted-external-keys` (byte-array-aware
   `value=`), and synthesizes `[:block-signed-by idx key]` facts for the
   authorizer.
3. Delegates to `datalog/eval-token`, which builds the origin-tagged fact
   store, runs the fixpoint, evaluates checks per block, and evaluates
   authorizer policies.

`eval-token` is the heart of the engine:

- **Origin tags.** Every fact carries its origin set: `#{0}` for block 0,
  `#{n}` for block N, `#{:authorizer}` for authorizer facts, and the union of
  matched origins plus the rule's block index for derived facts.
- **Fixpoint.** Rules fire to a fixpoint with per-block scope filtering,
  bounded by `:limits` (default 100 iterations / 1000 facts). Reaching a limit
  first throws, and the caller turns that into `{:valid? false :error
  {:type :limit-exceeded …}}` — a partial store is never evaluated, because a
  `:reject` check or `:deny` policy over a missing derived fact would pass.
- **Checks.** Evaluated once, after the fixpoint, per block with scoped
  visibility. `:one` (default) passes on a match; `:reject` passes on no
  match. No negation inside rule bodies — negative constraints are reject
  checks and deny policies.
- **Policies.** Authorizer-only, run in order after all checks pass. First
  match wins; no match is deny (closed world); no policies at all is allow.

### Scope isolation

Trusted origins per block:

- Block 0 (authority): `#{0 :authorizer}`
- Block N (N ≥ 1): `#{0 N :authorizer}`
- Authorizer: `#{0 :authorizer}` (extended with trusted third-party indices)

A fact is visible when its origin set is a subset of the trusted set. A later
block can therefore add checks (restrict) but can never add facts the
authorizer will see (expand). This is Biscuit's guarantee, and the tests pin
it well.

One subtlety worth documenting: within a round, blocks are processed in
order, and later blocks see facts derived by earlier blocks in the *same*
round (the store threads through the reduce). So block 1's rules can consume
block 0's freshly derived facts in one round. It's a reasonable semantics,
but it's asymmetric and currently undocumented.

### The fixpoint and fail-closed limits

`apply-rules-scoped` loops:

1. Compute `new-store` by threading through all blocks' rules.
2. If the fact count is unchanged → fixpoint reached, return.
3. If over `:max-facts` → throw `:limit-exceeded`.
4. If `rounds >= :max-iterations` → throw `:limit-exceeded`.
5. Otherwise recur.

The checks happen in this order, so a fixpoint reached exactly at the limit is
not an error (pinned by a test). Limits are configurable via `:limits`;
unknown keys or non-positive values throw. This is the right fail-closed
design and directly fixes the 0.11.0 bug where evaluation silently stopped
at a limit and evaluated the partial store.

### Expressions: `:when` / `:let`

`:when` guards and `:let` bindings are Clojure forms over a closed whitelist of
~35 functions (comparison, arithmetic, `str/…`, collections, type predicates,
regex) — no `eval`, no resolve, no namespace lookup, no I/O. Evaluation order:
pattern match → `:let` → `:when` → instantiate. Unbound variables and unknown
functions throw `ex-info`. This is a good security boundary: the token author
writes the guards, and there's no escape hatch.

### Explain and graph

`evaluate` with `:explain? true` returns a proof tree; `graph` turns it into
nodes and edges (deterministic `:n1, :n2, …` ids). The explain tree carries
per-check evidence (`:because`), per-rule proof lists, and synthetic
`:missing` nodes for failed checks. The graph is pure data transformation — no
authorization logic.

## Design commentary

### Strengths

- **Zero dependencies, single purpose.** The engine is embeddable anywhere and
  has no dependency chain to reason about.
- **Fail closed everywhere.** Limits, missing checks, no-matching policies,
  unknown keys in `:limits` — all deny or throw, never pass. The 0.12.0 fix is
  exactly right.
- **Pure core, thin shell.** `eval-token` is the only stateful-ish function;
  the pure helpers (`unify`, `eval-body`, `fire-rule`, `instantiate`) are
  independently testable.
- **Scope isolation by origin sets** — the right model for attenuation; the
  tests cover it thoroughly.
- **Closed expression whitelist** — a real security boundary, not a
  "trust the token author" shrug.
- **Explain/graph tooling** — audit trails and visualization are first-class.
- **Docs** — README, context.md, architecture docs, and the four historical
  reviews are honest about what moved where and what's stale.

### Tradeoffs worth noting

- **"No policies → allow"** is documented and deliberate (so checks-only
  evaluation works), but it is fail-open. An authorization engine where a
  missing policy list means allow is the one place the design isn't closed
  world. The checks still gate, so it's not unguarded — but it's a design
  question worth an explicit answer.
- **No CI config in this repo.** The uuidv7 project has `.github/workflows`;
  this one has none. Tests run via `clojure -X:test` manually. For a
  security-adjacent library, CI on push/PR would be a worthwhile gap to close.
- **Within-round block ordering** — later blocks see earlier blocks' derived
  facts in the same round. Undocumented; worth a sentence in the architecture
  docs.
- **`eval-body` is a nested loop** over body patterns × facts × states —
  exponential in body length in the worst case. Bounded by the fixpoint
  limits, but there's no cap on body length or rule count per block. Fine for
  typical token sizes; worth knowing for adversarial inputs.
- **`:when`/`:let` errors throw** rather than deny. An unbound variable or
  unknown function in a guard propagates out of `evaluate` as an
  `ex-info`, not a `{:valid? false}`. Defensible (it's a programming error),
  but it means the PDP must catch it or the decision never happens.
- **Explain tree shows only one check's evidence.** On success, `:explain` is
  the last check's explain; on failure, only the first failing check's. For
  audit, you'd want all failures and all passes.

## Findings

### Real

1. **Arity mismatch is silently accepted in `unify*`** — `(map vector pattern
   fact)` truncates to the shorter of the two, so a pattern with more elements
   than the fact unifies with the missing variables unbound, and a pattern
   with fewer elements than the fact unifies with the extra elements ignored.
   For rules this fails closed (unbound head vars → `nil` → no derivation).
   For **checks** it fails open: a check whose pattern has more arity than the
   fact matches and passes, with `:explain` carrying a `nil` fact. Concretely:
   `:query [[:user ?u ?role]]` against fact `[:user "alice"]` passes.
   Fix: require `(= (count pattern) (count fact))` before unifying.

2. **`graph` throws on the limit-exceeded explain tree.** When a limit is
   reached, `:explain` is the error map
   (`{:type :limit-exceeded :limit … :facts … :iterations …}`). `build-graph`
   on that node falls through to `:else` and throws "Unknown explain node
   shape". So `(sw/graph (:explain result))` on a fail-closed result crashes.
   Fix: handle the `:limit-exceeded` explain shape in `explain-node->graph-node`,
   or make `graph` accept the error map explicitly.

3. **The exception data leaks the full variable environment.** `eval-expr`
   throws `ex-info` with `{:variable form :env env}` — the entire env,
   including bound values (identifiers, maybe more), in the exception data.
   If this propagates to a caller that logs or serializes it, the env values
   leak. Fix: drop `:env` from the ex-data (or keep only the variable name).

### Minor / observations

- `normalize-facts`: a bare fact that is a 2-element vector whose first
  element is a set (`[#{0} [:foo]]`) would be misparsed as an already-normalized
  `[origin fact]` pair. Edge case; not reachable in practice for typical facts.
- `authorizer-with-signers` in `core.clj` uses `(update ... :facts into
  signer-facts)` — when the authorizer has no `:facts`, the `into` seed is nil.
  `insert-facts` handles seqs fine, so behavior is probably OK, but it's worth
  a test pinning the shape.
- `eval-check` in explain mode realizes all matches (`doall`) — fine for audit,
  but unbounded in principle (bounded only by the store limits).
- The graph for reject-pass checks renders `{:origin :reject-pass}` as an
  authority-fact node with a `nil` fact — harmless but awkward.
- `deps.edn` lists `"resources"` in `:paths` but no `resources/` directory
  exists. Harmless; worth cleaning up.
- `.cpcache/` is gitignored but present in the repo working tree — normal.
- `context.md` is at the repo root rather than in `docs/` — fine, but it's the
  kind of file that invites staleness; it's honest about it.

## Bottom line

The architecture is clean and the fail-closed design is right. The core engine
is solid, and the 0.12.0 limits fix was the right call. The actionable items
are: the arity-mismatch gap in `unify*` (real, fix before 0.13.0), the graph
crash on limit-exceeded explain trees, and the env leak in exception data.
Everything else is polish. No coding was done for this review; nothing in the
repo was modified.

---

## Open questions

- Should the arity-mismatch fix be strict (require equal arity) or lenient
  (allow fewer-element patterns to match, ignoring extra fact elements)?
  Strict is the safer default for an authorization engine.
- Should "no policies → allow" stay as-is, or become deny (fail closed)?
- Should the limit-exceeded explain tree be handled in `graph`, or should
  `graph` simply reject it with a clearer error?

---

## Decisions

- 2026-11-21 — Read-only review at v0.12.0; no files changed except this
  review. Tests not run; documented test counts cited as-is.