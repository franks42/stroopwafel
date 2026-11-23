# Project Review: stroopwafel

**Reviewer:** swival (inkling-2-mini)
**Date:** November 22, 2026
**Scope:** Architecture, design and code review of the engine at v0.12.0
**Method:** Read-only review — source, tests, docs, build. Tests were run (`clojure -X:test` → 71 tests / 146 assertions, 0 failures); every finding below was reproduced empirically with a throwaway script before being written down. No files in the repo were modified except this review.

---

## Overall

This is a disciplined, well-documented library. The 0.11.0 split into four layers (engine / signet / stroopwafel-pdp / PEP) is the right call: the engine is pure, zero-dependency and trusts its input, with all crypto and trust decisions pushed to the PDP. The fail-closed fixpoint limits in 0.12.0 fix a real, reproduced fail-open bug. Scope isolation via origin sets, the closed expression whitelist, the `:when`/`:let` guard design, and the explain tooling are all thoughtful.

This pass found **one authorization bypass**: `unify*` ignores arity, so patterns and facts of different lengths still match — and this lets through checks, rules _and_ allow policies (finding 1). It also found that the graph renderer cannot render the explain tree produced by `evaluate` on the happy path (finding 2), plus a few smaller items worth acting on. The prior review (Nov 21) flagged the arity mismatch (as checks-only) and a graph crash on limit-exceeded trees; both are confirmed, and this pass shows the arity issue is broader than reported.

_Revised 2026-11-23 after a second-opinion check: findings re-ranked (arity is now #1), the arity finding corrected (it fails open for rules and policies, not only checks), explain-output gaps added as finding 5, duplicate suggestions merged, and open question 1 moved to Decisions._

## What the project does

- **Library**: a pure Datalog engine for authorization decisions. Facts, rules, checks and policies go in; `{:valid? …}` comes out. RFC-style Datalog over plain vectors, with origin sets tracking which block a fact came from.
- **CLI**: none — by design. The engine is a library; the PEP is the caller.
- **Packaging**: JAR to Clojars (`com.github.franks42/stroopwafel`, v0.12.0) via tools.build. Runs on the JVM and babashka.
- **Consumers**: stroopwafel-pdp (SPKI/SDSI assertion pipeline), which verifies signatures and extracts facts before calling `evaluate`.

## How it works

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

This is the single most important design decision in the project. The engine knows nothing about crypto, envelopes, keys or HTTP. The PDP is the trust boundary: it verifies signatures and produces facts, and the engine trusts them. The README and context.md both state this explicitly. Good separation, and the zero-dependency property is what makes the engine embeddable.

### `evaluate` → `eval-token`

The public entry point (`stroopwafel.core/evaluate`) does three things:

1. Extracts logical content (`:facts` / `:rules` / `:checks`) from each block, dropping `:external-key` (used only for trust computation, not passed down).
2. Computes which third-party blocks are trusted by comparing `:external-key` bytes against the authorizer's `:trusted-external-keys` (byte-array-aware `value=`), and synthesizes `[:block-signed-by idx key]` facts for the authorizer.
3. Delegates to `datalog/eval-token`, which builds the origin-tagged fact store, runs the fixpoint, evaluates checks per block, and evaluates authorizer policies.

`eval-token` is the heart of the engine:

- **Origin tags.** Every fact carries its origin set: `#{0}` for block 0, `#{n}` for block N, `#{:authorizer}` for authorizer facts, and the union of matched origins plus the rule's block index for derived facts.
- **Fixpoint.** Rules fire to a fixpoint with per-block scope filtering, bounded by `:limits` (default 100 iterations / 1000 facts). Reaching a limit first throws, and the caller turns that into `{:valid? false :error {:type :limit-exceeded …}}` — a partial store is never evaluated, because a `:reject` check or `:deny` policy over a missing derived fact would pass.
- **Checks.** Evaluated once, after the fixpoint, per block with scoped visibility. `:one` (default) passes on a match; `:reject` passes on no match. No negation inside rule bodies — negative constraints are reject checks and deny policies.
- **Policies.** Authorizer-only, run in order after all checks pass. First match wins; no match is deny (closed world); no policies at all is allow.

### Scope isolation

Trusted origins per block:

- Block 0 (authority): `#{0 :authorizer}`
- Block N (N ≥ 1): `#{0 N :authorizer}`
- Authorizer: `#{0 :authorizer}` (extended with trusted third-party indices)

A fact is visible when its origin set is a subset of the trusted set. A later block can therefore add checks (restrict) but can never add facts the authorizer will see (expand). This is Biscuit's guarantee, and the tests pin it well.

One subtlety worth documenting: within a round, blocks are processed in order, and later blocks see facts derived by earlier blocks in the *same* round (the store threads through the reduce). So block 1's rules can consume block 0's freshly derived facts in one round. It's a reasonable semantics, but it's asymmetric and currently undocumented.

### The fixpoint and fail-closed limits

`apply-rules-scoped` loops:

1. Compute `new-store` by threading through all blocks' rules.
2. If the fact count is unchanged → fixpoint reached, return.
3. If over `:max-facts` → throw `:limit-exceeded`.
4. If `rounds >= :max-iterations` → throw `:limit-exceeded`.
5. Otherwise recur.

The checks happen in this order, so a fixpoint reached exactly at the limit is not an error (pinned by a test). Limits are configurable via `:limits`; unknown keys or non-positive values throw. This is the right fail-closed design and directly fixes the 0.11.0 bug where evaluation silently stopped at a limit and evaluated the partial store.

### Expressions: `:when` / `:let`

`:when` guards and `:let` bindings are Clojure forms over a closed whitelist of ~35 functions (comparison, arithmetic, `str/…`, collections, type predicates, regex) — no `eval`, no resolve, no namespace lookup, no I/O. Evaluation order: pattern match → `:let` → `:when` → instantiate. Unbound variables and unknown functions throw `ex-info`. This is a good security boundary: the token author writes the guards, and there's no escape hatch.

### Explain and graph

`evaluate` with `:explain? true` returns a proof tree; `graph` turns it into nodes and edges (deterministic `:n1, :n2, …` ids). The explain tree carries per-check evidence (`:because`), per-rule proof lists, and synthetic `:missing` nodes for failed checks. The graph is pure data transformation — no authorization logic.

**This is where the happy path breaks down** — see Findings below.

## Design commentary

### Strengths

- **Zero dependencies, single purpose.** The engine is embeddable anywhere and has no dependency chain to reason about.
- **Fail closed everywhere.** Limits, missing checks, no-matching policies, unknown keys in `:limits` — all deny or throw, never pass. The 0.12.0 fix is exactly right.
- **Pure core, thin shell.** `eval-token` is the only stateful-ish function; the pure helpers (`unify`, `eval-body`, `fire-rule`, `instantiate`) are independently testable.
- **Scope isolation by origin sets** — the right model for attenuation; the tests cover it thoroughly.
- **Closed expression whitelist** — a real security boundary, not a "trust the token author" shrug.
- **Explain tooling** — audit trails are first-class (though see Findings).
- **Docs** — README, context.md, architecture docs, and the four historical reviews are honest about what moved where and what's stale.

### Tradeoffs worth noting

- **"No policies → allow"** is documented and deliberate (so checks-only evaluation works), but it is fail-open. An authorization engine where a missing policy list means allow is the one place the design isn't closed world. The checks still gate, so it's not unguarded — but it's a design question worth an explicit answer.
- **No CI config in this repo.** There is no `.github/workflows`; tests run via `clojure -X:test` manually. For a security-adjacent library, CI on push/PR would be a worthwhile gap to close.
- **Within-round block ordering** — later blocks see earlier blocks' derived facts in the same round. Undocumented; worth a sentence in the architecture docs.
- **`eval-body` is a nested loop** over body patterns × facts × states — exponential in body length in the worst case. Bounded by the fixpoint limits, but there's no cap on body length or rule count per block. Fine for typical token sizes; worth knowing for adversarial inputs.
- **`:when`/`:let` errors throw** rather than deny. An unbound variable or unknown function in a guard propagates out of `evaluate` as an `ex-info`, not a `{:valid? false}`. Defensible (it's a programming error), but it means the PDP must catch it or the decision never happens.
- **Explain tree shows only one check's evidence.** On success, `:explain` is the last check's explain; on failure, only the first failing check's. For audit, you'd want all failures and all passes.

## Findings

### Real

1. **Arity mismatch is silently accepted in `unify*` — authorization bypass** — _critical; confirmed from prior review, scope corrected_. `(map vector pattern fact)` (datalog.clj:130) truncates to the shorter of the two, so a pattern with more elements than the fact unifies with the missing variables unbound, and a pattern with fewer elements than the fact unifies with the extra elements ignored. This fails open everywhere patterns are matched — checks, rule bodies and authorizer policies. Reproduced via `sw/evaluate`:
   ```clojure
   ;; shorter allow-policy pattern matches a longer fact
   ;; fact [:right "alice" :read], policy {:kind :allow :query [[:right ?u]]}
   ;; => {:valid? true}

   ;; longer rule-body pattern still derives when the head doesn't use the missing var
   ;; fact [:user "alice"], rule {:head [:admin ?u] :body [[:user ?u ?x]]},
   ;; policy {:kind :allow :query [[:admin ?u]]}
   ;; => {:valid? true}

   ;; check with longer pattern passes, explain carries a nil fact
   ;; eval-check {:id :c1 :query '[[:user ?u ?role]]} {[:user "alice"] #{0}}
   ;; => {:result :pass, :explain {... :because {:origin #{0} :fact nil}}}
   ```
   The earlier claim that rules "fail closed" holds only when the head references a missing variable. Fix: require `(= (count pattern) (count fact))` before unifying. There is no safe lenient variant — "ignore extra fact elements" is exactly the bypass above.

2. **The graph renderer cannot render the explain tree produced by `evaluate` on the happy path** — _high severity, untested_. In `eval-check` (datalog.clj:497–504), when a check passes and the matched fact is found in the store lookup, `:because` is set to `(get fact-lookup fact)` — an **origin set** like `#{0}` or `#{:authorizer}`, not a map. The graph's `build-graph` then recurses into that set as if it were an explain node; every branch in `explain-node->graph-node` fails (a set is not a map) and the function throws "Unknown explain node shape". Reproduced with the README's own example:
   ```clojure
   ;; valid? => true, but graph throws
   (sw/evaluate token :explain? true :authorizer {...})
   ;; => {:valid? true :explain {:type :check :check-id :not-expired
   ;;                              :result :pass :because #{:authorizer} ...}}
   (sw/graph (:explain result)) ; throws "Unknown explain node shape"
   ```
   The graph tests pass only because they hand-craft map-shaped `:because` nodes (with a `:rule` key or an explicit `{:origin ... :fact ...}` fallback) that never occur in real output. No test pipes `evaluate` → `graph` together, which is why this gap survived. Fix: either make `eval-check` always emit a map-shaped `:because` (e.g. `{:origin <set> :fact <fact>}`), or teach `explain-node->graph-node` to handle bare origin sets as authority-fact nodes. The first is cleaner and matches the existing fallback shape.

   **Deeper issue:** either fix stops the crash, but the graph stays flat. `eval-check` never records which rule derived a fact — `:because` is only ever an origin set or `{:origin … :fact …}` — so the graph's derived-fact branch (`derived-node?`, keyed on `:rule`) is reached only by the hand-crafted test data. The explain producer and the graph consumer disagree on the tree's shape; the real fix is to decide whether explain carries rule proofs (the `:proof` that `unify`/`eval-body` already accumulate) and align one side to the other.

3. **The graph throws on the limit-exceeded explain tree** — *confirmed from prior review*. When a limit is reached, `:explain` is the error map (`{:type :limit-exceeded :limit … :facts … :iterations …}`). `build-graph` on that node falls through to `:else` and throws "Unknown explain node shape". So `(sw/graph (:explain result))` on a fail-closed result crashes. Fix: handle the `:limit-exceeded` explain shape in `explain-node->graph-node`, or make `graph` accept the error map explicitly and return a small graph with an error node.

4. **The exception data leaks the full variable environment** — _new in this pass_ (the Nov 21 review does not mention it). `eval-expr` throws `ex-info` with `{:variable form :env env}` — the entire env, including bound values (identifiers, maybe more), in the exception data. Reproduced:
   ```clojure
   ;; eval-expr '?x {'?t 500} => ex-data {:variable ?x :env {?t 500}}
   ```
   If this propagates to a caller that logs or serializes it, the env values leak. Fix: drop `:env` from the ex-data (or keep only the variable name).

5. **The explain output omits the decision's actual basis** — _medium; audit gap_. In `eval-token` (datalog.clj:660–676):
   - On success, `:explain` is the _last_ check's explain only; on failure, the _first_ failing check's only.
   - A token with no checks returns `{:valid? true :explain nil}` (reproduced), so there is nothing to audit or graph.
   - The policy that decided the outcome is never named: an allow is not recorded at all, and a deny is `{:type :policy :result :deny}` with no policy id or query.

   Fix: return every check result plus the matching policy (id, kind, bindings) in explain mode.

### Minor / observations

- **`normalize-facts` edge case** — a bare fact that is a 2-element vector whose first element is a set (`[#{0} [:foo]]`) would be misparsed as an already-normalized `[origin fact]` pair. Edge case; not reachable in practice for typical facts, but worth a comment or a guard.
- **`authorizer-with-signers`** in `core.clj` uses `(update ... :facts into signer-facts)` — when the authorizer has no `:facts`, the `into` seed is nil. `insert-facts` handles seqs fine, so behavior is probably OK, but it's worth a test pinning the shape.
- **`eval-check` in explain mode realizes all matches** (`doall`) — fine for audit, but unbounded in principle (bounded only by the store limits).
- **The graph for reject-pass checks renders `{:origin :reject-pass}` as an authority-fact node with a `nil` fact** — harmless but awkward.
- **`deps.edn` lists `"resources"` in `:paths` but no `resources/` directory exists.** Harmless; worth cleaning up.
- **`context.md` is at the repo root rather than in `docs/`** — fine, but it's the kind of file that invites staleness; it's honest about it.
- **No test pipes `evaluate` → `graph` together.** This is why finding 2 survived; see suggestion 2.

## Suggestions for improvement

1. **Require equal arity in `unify*` first** — it's an authorization bypass (finding 1). Add regression tests for all three paths: check, rule body, allow policy.
2. **Fix the happy-path graph crash** (finding 2) — normalize `:because` to a map in `eval-check`, and decide whether explain should carry rule proofs. Add an end-to-end test that pipes `evaluate` → `graph` (README example, plus a limit-exceeded case); this one test would have caught findings 2 and 3.
3. **Add CI** (GitHub Actions) running `clojure -X:test` on push/PR. For a security-adjacent library, this is cheap and high-value.
4. **Drop `:env` from exception data** in `eval-expr` (and audit other ex-info sites) so bound values don't leak into logs or serialized errors.
5. **Handle the limit-exceeded explain shape in `graph`** — either render it as an error node or reject it with a clearer message than "Unknown explain node shape".
6. **Document within-round block ordering** (later blocks see earlier blocks' derived facts in the same round) in the architecture docs and README.
7. **Consider whether "no policies → allow" should stay as-is** — it's documented and deliberate, but it is fail-open. An explicit answer in the design docs would help consumers decide.
8. **Clean up `deps.edn`** (remove the nonexistent `resources/` path) and add a test pinning the `authorizer-with-signers` nil-seed shape.
9. **Return all check results and the deciding policy in explain mode** (finding 5), so audit trails show every check's outcome and why the decision was made.

## Bottom line

The architecture is clean and the fail-closed design is right. The core engine is solid, and the 0.12.0 limits fix was the right call. The actionable items are: the arity-mismatch bypass in `unify*` (critical — fails open for checks, rules and policies; fix before 0.13.0), the happy-path graph crash (high severity, untested), the limit-exceeded graph crash, the env leak in exception data, and the explain-output gaps. Everything else is polish. No coding was done for this review; nothing in the repo was modified except this review file.

---

## Open questions

- ~~Should the arity-mismatch fix be strict (require equal arity) or lenient (allow fewer-element patterns to match, ignoring extra fact elements)? Strict is the safer default for an authorization engine.~~ Resolved — see Decisions.
- Should "no policies → allow" stay as-is, or become deny (fail closed)?
- Should the limit-exceeded explain tree be handled in `graph`, or should `graph` simply reject it with a clearer error?
- ~~Should `eval-check` always emit map-shaped `:because` nodes, or should `graph` handle bare origin sets? (Both are valid; the first is cleaner.)~~ Superseded — `:because` becomes proof nodes; see Decisions.
- ~~Should the explain tree carry rule-derivation proofs (so the graph can show _why_ a derived fact exists), or should the graph's derived-fact branch be removed as unreachable?~~ Resolved — see Decisions.
- Should arity be enforced at match time only, or also validated up front (rule/check/policy patterns vs. known predicate arities) so mistakes surface as errors rather than silent non-matches?
- ~~All-reasons explain: show circular derivations (honest: every edge is a valid rule application; the graph shows the loop), mark them, or filter to non-circular reasons only (clearer for tutorials, but a correct filter is a real well-foundedness computation, not a cheap check)?~~ Resolved — see Decisions.
- ~~All-reasons explain: is a flat `fact → [derivations]` table acceptable for `:all` mode, while `true` keeps the nested tree — or should both modes switch to the flat table so there's one shape?~~ Resolved — see Decisions.

---

## Decisions

- ~~2026-11-22 — Read-only review at v0.12.0; no files changed except this review. Tests were run (71 tests / 146 assertions, 0 failures) and every finding was reproduced empirically before being written down.~~ (Review method, not a decision; already stated in the header's **Method** line.)
- 2026-11-23 — Arity in `unify*` is strict (equal length required); the lenient variant is the bypass itself.
- 2026-11-23 — Explain carries rule-derivation proofs (option A): showing which rules and facts led to a decision is essential for debugging, audit, and tutorials. Details in **Rule proofs in explain** below.
- 2026-11-23 — `:explain? :all` shows every derivation, circular ones included: tutorials should show circular reasons, not hide them, and every step is a valid rule application.
- 2026-11-23 — One flat explain shape for both `true` and `:all` (fact table + derivation nodes), replacing the nested tree: one format for consumers, and the only shape that can hold cycles.

### Rule proofs in explain

_The nested-tree shape below is superseded by the flat shape in **All reasons in explain**; what is recorded, and one derivation per fact for `:explain? true`, still apply._

- **Record:** with `:explain? true`, the fixpoint keeps a side map `derived fact → {:rule :block :env :proof}`; no cost when explain is off.
- **One proof per fact:** the first derivation found (the store already ignores later ones). That is "a reason", not every reason, and a proof only refers to earlier facts, so recursive rules can't create cycles.
- **`:because`:** for a passing check, one proof node per matched body fact (fixes join checks being explained by their first pattern only). A derived fact expands to its rule, block, bindings and its own proof, down to stated facts; a stated fact is a leaf with its origin.
- **`graph`:** uses the existing derived-fact branch; repeated facts become one node, so shared sub-proofs don't blow up the graph.
- **Replaces** the planned finding-2 fix (map-shaped `:because`).

### All reasons in explain

Requested 2026-11-23: optionally show _every_ derivation of a fact, not just the first, for debugging, audit and tutorials.

- **Option:** `:explain? :all` (`true` stays one reason per fact).
- **Finding them is cheap:** the fixpoint re-fires every rule over every visible fact each round, so the final round enumerates every derivation over the final store. Recording them is a set per fact instead of a single entry.
- **Catch — cycles:** with all derivations, proofs can loop. Edges `1→2`, `2→1` with a transitive `:path` rule: `[:path 1 2]` follows from `[:edge 1 2]`, but also from `[:path 1 1]` + `[:edge 1 2]`, and `[:path 1 1]` follows from `[:path 1 2]` + `[:edge 2 1]`. Each step is a valid rule application, but the pair is a circular "reason".
- **So the shape changes:** a nested tree can't hold a cycle. In `:all` mode explain would carry a flat table `fact → [derivation …]`, with `:because` and each `:proof` referring to facts in it; `graph` already merges facts into single nodes, so it draws cycles as edges back to an existing node.
- **Cost:** derivations can far outnumber facts (dense transitive closure). A cap — say `:max-derivations`, default 10 000 — that _truncates and flags_ `:truncated? true` rather than denying, since explain data never changes the decision.

**Shape (both modes):** a check's explain is

```clojure
{:type :check :check-id :c :result :pass
 :because [fact …]                 ; facts that justify the result
 :matches [{:env {…} :origin #{…} :facts [fact …]} …]
 :facts   {fact {:origin #{…}
                 :stated? true     ; present when a block stated it
                 :derivations [{:rule :r :block 1 :env {…} :proof [fact …]} …]}}
 :truncated? true}                 ; only when the derivation cap was hit
```

- `:because`: with `true`, the facts of the first match; with `:all`, every fact of every match.
- `:facts`: every fact reachable from `:because` through `:proof`, each once; cycles are just facts referring back.
- `graph`: nodes `:check`, `:fact`, `:derivation`, `:missing-fact`; edges check `:because`/`:rejected-by`/`:missing` → fact, fact `:derived-by` → derivation, derivation `:uses` → fact. A derivation node keeps a rule's premises together, so two derivations of one fact stay distinct.
