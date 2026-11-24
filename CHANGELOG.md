# Changelog

All notable changes to stroopwafel. Each entry reflects committed work.
History before 0.13.0 is in `context.md` (## History).

## Unreleased (0.16.1)

### Fixed

- **The arity check only counts keyword predicates.** It took the first
  element of every fact and pattern for a predicate, so positional
  records led by a value — stroopwafel-pdp stores assertions as
  `[signer ts not-before not-after :type id & args]` — were reported as
  one "predicate" (the signer's key id) with several lengths. With
  0.16.0's `:error` default that denied every decision on them. Patterns
  that start with a value or a variable are now skipped.

## 0.16.0 — 2026-11-24

From the second review (`docs/review2-swival-inkling-2-mini.md`).

### Breaking

- **`:arity-check` defaults to `:error`**: a predicate used with
  different lengths now denies (`:reason :arity-mismatch`, the
  mismatches in `:error`) instead of only adding a warning. A mismatched
  pattern never matches, so a reject check or deny policy with a typo
  silently never fired — a fail-open that only callers reading
  `:warnings` noticed. It is still a decision, not a throw. `:arity-check
  :warn` keeps the old behaviour, `:off` skips the check.

### Added

- **The graph keeps error details**: when a limit or an arity mismatch
  denied before any check ran, the `:decision` node carries the `:error`
  (limit, max and counts, or the mismatches); it used to show only the
  reason.

### Fixed

- `normalize-facts` (used by `eval-body`) takes `[set x]` for an
  `[origin fact]` pair only when `x` is a vector, so an odd bare fact
  like `[#{0} :x]` is no longer misread.

### Docs and tests

- `arity-mismatches` documents its location keys; the README shows
  treating every warning as an error.
- `explain-all-matches-naive-oracle`: on 400 random programs, the
  derivations `:explain? :all` records are exactly those that re-firing
  every rule finds (1213 derivations). The graph of a limit-exceeded
  decision is tested with `:explain? :all` too.

## 0.15.0 — 2026-11-23

### Breaking

- **No policies denies** instead of allowing, with `:reason
  :no-policies` in the explain and a `{:type :no-policies}` warning in the
  result. It was the one fail-open default left: a forgotten authorizer
  allowed any token whose checks passed (a token without checks always).
  The decision stays binary — only a matching `:allow` allows — and the
  reason tells callers what happened; one that treats a missing policy set
  as an error can throw on the warning (README). To let checks alone
  decide, add `{:kind :allow :query []}`, which matches unconditionally.
- **Unknown keys throw** (`:stroopwafel/error :unknown-keys`, with
  `:unknown` and `:allowed`): options to `evaluate` and `eval-token`, and
  `:authorizer` keys. `:authoriser` used to drop the authorizer silently —
  with a deny policy in it, the token passed; `:check` dropped checks.
- **Explain:** `:reason :no-policies` is now a deny. The explicit
  allow-all policy shows as a matched policy with an empty `:because`.
- The rule behind both: the decision depends only on the data (token and
  policies); only a malformed call throws.

## 0.14.2 — 2026-11-23

### Performance

- **Semi-naive evaluation.** A block's later turns in the fixpoint match
  only rule bodies that use a (fact, origin set) entry inserted since its
  previous turn; a block with nothing new is skipped. Each round still
  derives exactly what re-firing every rule would, so stores, decisions,
  round counts and limits are unchanged, and so is every derivation
  `:explain? :all` records. `:explain? true` may keep a different (equally
  valid) first derivation of a fact.
- **Predicate index.** A pattern only scans facts with its predicate and
  length.
- Transitive closure over 50 edges: 6.4 s → 0.1 s; a 400-step chain:
  8.6 s → 0.17 s (JVM). The babashka test suite runs in under a second.

### Tests

- `fixpoint-matches-naive-oracle`: the engine's store against a naive
  fixpoint written in the test, on 400 random seeded programs (multiple
  blocks, recursion, third-party scopes).

## 0.14.1 — 2026-11-23

### Security

- **The fixpoint could stop before every scope derived from a fact**
  (high; 0.14.0 only, introduced by its fix). It stopped when the number
  of (fact, origin set) entries was unchanged, but a smaller origin set
  replacing a kept superset leaves the count unchanged while making the
  fact visible to more scopes. An appended block could use this to keep
  block 0 from deriving a revocation the authorizer rejects on, making a
  revoked token valid. The fixpoint now stops only when a round leaves the
  store unchanged. Exploit and workaround: the addendum to
  `docs/security-advisory-2026-11-23-origin-hiding.md`.

## 0.14.0 — 2026-11-23

_Affected by the early-stop issue fixed in 0.14.1; don't deploy it._

### Security

- **An appended block could hide facts from the authorizer** (critical;
  0.2.0 through 0.13.0). The fact store kept one origin set per fact —
  the first derivation's, or the union when a fact was stated twice — so
  a block appended to a token could give a fact an origin set the
  authorizer cannot see. Behind a reject check or deny policy that fails
  open: a revoked token became valid by appending a block that derived
  the authorizer's `[:revoked …]` first, or restated its
  `[:revocation-entry …]`. The store now keeps every minimal origin set
  per fact, and a scope sees a fact through any of them. Details,
  exploits and workarounds: `docs/security-advisory-2026-11-23-origin-hiding.md`.
  There are no known users of the affected releases, so this changelog
  entry and the advisory are the only disclosure.

### Breaking

- **Fact store shape:** `{fact #{origin-set …}}` (was `{fact
  origin-set}`). `insert-fact` keeps minimal origin sets and never unions;
  new `adds-origin?` and `origin-count`.
- **`:max-facts` counts (fact, origin set) entries**, not distinct facts,
  so appended blocks re-deriving the same facts cannot grow the store
  without bound. Tokens whose facts hold several origin sets reach the
  limit sooner.
- **Explain:** the fact table reports `:origins` (a set of origin sets)
  instead of `:origin`; each derivation carries the `:origin` it
  produced. `graph` fact nodes have `:origins`; derivation nodes have
  `:origin`.
- Decisions change where a fact used to be hidden: tokens that wrongly
  passed now deny, and tokens where a later block hid a block-0 fact from
  the authorizer now pass.

### Docs

- README and `context.md` no longer claim block order "cannot change the
  fixpoint" without qualification: it can't now that every origin set is
  kept, but with one origin per fact it changed what each scope saw.

## 0.13.0 — 2026-11-23

_Affected by the origin-hiding issue fixed in 0.14.0; don't deploy it._

### Breaking

- **Patterns match only facts of the same length.** `unify*` used to zip
  pattern and fact, truncating to the shorter, so a pattern of another
  length still matched. That let checks, rule bodies and allow policies
  through (an authorization bypass). Tokens that relied on it now deny.
- **`:explain` is a decision map**, not a single check's explain:
  `{:type :decision :result :reason :checks :policies :facts}`. See
  _Explain_ below.
- **Error data no longer carries values.** An unbound variable in
  `:when`/`:let` throws with `{:variable ?x}` only (was `{:variable ?x
  :env {…}}`). `graph`'s "Unknown explain node shape" error carries
  `{:node-keys :node-class}` only (was the whole node).
- **`graph` output:** node kinds are `:decision`, `:check`, `:policy`,
  `:fact`, `:derivation`, `:missing-fact`; edges are `:check`, `:policy`,
  `:because`, `:rejected-by`, `:missing`, `:derived-by`, `:uses`. The
  public helpers `build-graph`, `explain-node->graph-node` and the node
  constructors are removed; `explain->graph` and `sw/graph` remain.
- **`eval-policy`** returns an extra `:explain` key.

### Explain

- Shows the whole decision: `:reason` (`:policy`, `:check-failed`,
  `:no-policies`, `:no-matching-policy`, `:limit-exceeded`), every check
  with its `:block`, and every policy evaluated up to the deciding one
  with its `:index`. The deciding policy carries `:because` and
  `:matches`. A token without checks no longer gives `nil`.
- Shows how derived facts came about: one `:facts` table gives each
  fact's origin, whether a block stated it, and the rules that derived
  it (rule, block, bindings, the facts used), down to stated facts.
- A check's `:because` covers every pattern of a join (it used to show
  only the first). A failed reject check lists the facts that triggered
  it.
- `:explain? :all` keeps every derivation of every fact, circular ones
  included; `:explain? true` keeps the first found.
- New limit `:max-derivations` (default 10 000) caps explain data. Past
  it the explain is flagged `:truncated?`; the decision is unchanged.
- The decision and its explain come from one function, so they cannot
  disagree.

### Fixed

- `graph` threw on every passing `evaluate` result (`:because` was a bare
  origin set) and on a limit-exceeded result.
- Bound values (identifiers) could leak into logs via exception data.

### Added

- `fixpoint` (returns the store and recorded derivations);
  `apply-rules-scoped` still returns the store.
- CI: GitHub Actions runs the tests on the JVM and on babashka, and
  builds the JAR, on pushes to `main` and on pull requests.
- `bb test:bb` runs the test suite under babashka.
- `sw/check-arity` (and `datalog/arity-mismatches`) list predicates used
  with different lengths across facts, rule heads and bodies, checks and
  policies, with where each length occurs. Run it on a policy set before
  storing it.
- `evaluate` option `:arity-check`: `:warn` (default) adds `:warnings`
  to the result when lengths disagree, leaving the decision alone;
  `:error` denies with `{:type :arity-mismatch :mismatches [...]}`;
  `:off` skips the check. Unknown values throw.

### Docs and housekeeping

- README and `context.md` describe the explain shape and the order in
  which blocks see each other's derived facts within a round.
- `deps.edn` no longer lists the nonexistent `resources/` path.
- Reviews of 0.12.0 kept in `docs/`; the Nov 21 one is marked superseded.
  Remaining work is tracked in `docs/TODO.md`.
