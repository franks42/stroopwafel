# Changelog

All notable changes to stroopwafel. Each entry reflects committed work.
History before 0.13.0 is in `context.md` (## History).

## 0.13.0 — 2026-11-23

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
