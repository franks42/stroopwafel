# Project Review 2: stroopwafel

**Reviewer:** swival (inkling-2-mini)
**Date:** November 22, 2026
**Scope:** Follow-up review of the fixes applied to v0.12.0 — verifying each finding from `docs/review-swival-inkling-2-mini.md` and checking for new issues introduced by the changes (v0.13.0 → v0.15.0)
**Method:** Read-only review — source, tests, docs, build, CI config. Tests were run on both JVM and babashka (118 tests / 650 assertions, 0 failures each); every finding below was reproduced empirically with a throwaway script before being written down. No files in the repo were modified except this review.

---

## Overall

The fixes are thorough and well-tested. Every finding from my first pass is addressed, plus several security-critical issues that went beyond what I flagged — most importantly the origin-hiding bug (0.2.0–0.13.0), which was critical: an appended block could hide authorizer facts behind reject checks and deny policies, making a revoked token valid. The fix keeps every minimal origin set per fact, with regression tests and a security advisory.

The changes are also well-documented: the README, context.md, CHANGELOG.md and docs/TODO.md all describe the new behavior accurately, and the CI workflow runs on both JVM and babashka. The semi-naive fixpoint is tested against a naive oracle on 400 random programs.

This pass found **no correctness bugs in the happy path**, but a few smaller items worth acting on — mostly polish rather than security issues. One design question remains open (the `:arity-check :warn` default) and one edge case from my first review is still unfixed (the `normalize-facts` misparse).

## What changed since the first review

| Commit | Change | Addresses |
| ------ | ------- | --------- |
| `f0a166a` | Strict arity in `unify*` — require equal length | Finding 1 (authorization bypass) |
| `20c166f` | Explain carries rule-derivation proofs; graph renders evaluate output | Finding 2 (happy-path graph crash) |
| `8875e0e` | Explain: every reason on request (`:explain? :all`), one flat shape | Finding 5 (explain shows only one check's evidence) |
| `3585daa` | Explain the whole decision: every check, every policy, a reason | Finding 5 |
| `f192316` | Keep bound values and facts out of ex-data | Finding 4 (env leak) |
| `0bee5a3` | Check pattern lengths up front: `check-arity` + `:arity-check` | Finding 1 (up-front validation) |
| `57daa63` | CI on JVM and babashka; changelog; review TODO cleanups | Minor item (no CI) |
| `31256c5` | Keep every origin set per fact: appended blocks could hide facts | Finding 6 (critical, new) |
| `57d3994` | Stop the fixpoint only when the store is unchanged | 0.14.0 early-stop bug (new) |
| `de4ecdd` | Semi-naive fixpoint and predicate index | Performance (~50× faster) |
| `0b9ea14` | No policies denies with a warning; unknown keys throw | Minor item (no policies → allow) + new |
| `18412b3` / `3396559` | Bump to 0.15.0; TODO cleanup | Release |

## Verification of each finding from the first review

### Finding 1: Arity mismatch in `unify*` — **fixed**

`unify*` now requires `(= (count pattern) (count fact))` before unifying. Reproduced:
```clojure
;; unify '[:user ?u ?role] [:user "alice"] => nil  (was {:env {?u "alice"} ...})
;; eval-check with extra var vs short fact => {:result :fail, :explain {... :missing [[:user ?u ?role]]}}
```
The check now fails closed instead of passing. Additionally, `sw/check-arity` and the `:arity-check` option (`:warn` default, `:error`, `:off`) catch predicates used with different lengths across facts, rule heads and bodies, checks and policies — before evaluation. Reproduced:
```clojure
;; check-arity on a mismatched policy => [{:predicate :user, :arities {2 [...], 3 [...]}}]
;; evaluate with :arity-check :error => valid?= false, error= {:type :arity-mismatch ...}
```
The `:warn` default adds `:warnings` without changing the decision; `:error` denies before evaluating. This is a good design — it catches typos in reject checks and deny policies that would otherwise silently never fire.

### Finding 2: Graph crash on happy-path explain tree — **fixed**

`eval-check` now emits map-shaped evidence (`:because` is a vector of facts, not an origin set). The graph renderer handles the new flat decision shape (`:decision` root with `:checks` and `:policies` children). Reproduced with the README's own example:
```clojure
;; valid? => true, GRAPH OK root= :n1 nodes= 9 edges= 9
```
End-to-end tests added (README example → graph, limit-exceeded, reject-pass, no checks, derived-fact, join, shared-fact, cycles, policies). The graph tests now use hand-built explain maps in the flat shape that `evaluate` actually produces — not the old map-shaped `:because` nodes that never occurred in real output.

### Finding 3: Graph crash on limit-exceeded explain tree — **fixed**

The explain is now a decision map with `:reason :limit-exceeded`; graph renders it as a single decision node. Reproduced:
```clojure
;; valid? => false, reason => :limit-exceeded, GRAPH OK nodes= 1
```
Works for both `:explain? true` and `:explain? :all` modes.

### Finding 4: Env leak in exception data — **fixed**

`eval-expr` throws with only `{:variable ?x}` (no env). Reproduced:
```clojure
;; eval-expr '?x {'?t 500} => ex-data {:variable ?x}
```
The graph's "Unknown explain node shape" error also carries only `{:node-keys :node-class}` (no facts or bindings). The limit-exceeded error data carries only config/counts (limit, max, facts, iterations) — no bound values.

### Finding 5: Explain shows only one check's evidence — **fixed**

The explain is now the whole decision: `{:type :decision :result :reason :checks [...] :policies [...] :facts {...}}`. Every check with its block and result, every policy evaluated up to the deciding one (with index), and one fact table for all of them. Reproduced:
```clojure
;; explain type => :decision
;; checks => []  (or [{:type :check :check-id ... :block 0 :result :pass}])
;; policies => [{:kind :allow :query [[:user ?u]] :result :matched :because [[:user alice]] :index 0}]
```
`:explain? true` keeps the first derivation of each fact; `:explain? :all` keeps every derivation, circular ones included, up to `:max-derivations` (default 10 000). Past the cap the explain is flagged `:truncated?` without changing the decision — verified empirically.

### Finding 6: Origin hiding (critical, new from revised first review) — **fixed**

The fact store now maps each fact to the set of minimal origin sets it was found with (`{fact #{origin-set …}}`). A scope sees a fact through any of its origin sets. `insert-fact` keeps only minimal origin sets and never unions; `adds-origin?` and `origin-count` are new helpers. The fixpoint ends when the store is unchanged (not merely when the count stops changing — that was the 0.14.0 bug, fixed in 0.14.1). Reproduced:
```clojure
;; appended block cannot hide a revocation => valid?= false (was true on affected versions)
;; origin replacement does not end the fixpoint => regression test passes
```
Regression tests added for both exploits in the advisory, plus unit tests of the store. The security advisory documents the exploits, workarounds and compatibility notes. This is a thorough fix — arguably more important than any finding from my first pass.

### Minor items from the first review — all addressed

- **No CI config** → GitHub Actions workflow (`.github/workflows/test.yml`) runs tests on JVM and babashka, plus JAR build, on pushes to `main` and PRs. Verified: both runners pass locally (118 tests / 650 assertions each).
- **Within-round block ordering undocumented** → Documented in README (model section) and context.md (engine section). The docs now also note that the order cannot change what any scope sees — only round count and which derivation `:explain? true` reports first.
- **No policies → allow (fail open)** → Fixed as a breaking change in 0.15.0. No policies now denies with `:reason :no-policies` and a `{:type :no-policies}` warning. Explicit allow-all via `{:kind :allow :query []}`. Reproduced:
```clojure
;; no policies => valid?= false, warnings= [{:type :no-policies}]
;; explicit allow-all => valid?= true, warnings= nil
```
- **deps.edn resources path** → Removed (`resources/` never existed).
- **authorizer-with-signers nil seed** → Test added (`signer-facts-without-authorizer-facts`); verified empirically that the `into` with a nil seed works correctly.
- **Explain shows only one check's evidence** → Fixed (see Finding 5 above).
- **Unknown keys throw** → New in 0.15.0: unknown options and authorizer keys throw `:stroopwafel/error :unknown-keys` with `:unknown` and `:allowed`. Reproduced:
```clojure
;; :authoriser => Unknown evaluate options: [:authoriser]; expected some of (...)
;; :check => Unknown authorizer keys: [:check]; expected some of (...)
```
This is a good addition — it closes the "typo silently drops the authorizer and its deny policies" gap.

## New issues found in this pass

### Real

1. **The `normalize-facts` edge case still exists** — *minor, not reachable in practice*. A bare fact that is a 2-element vector whose first element is a set (`[#{0} [:foo]]`) would be misparsed as an already-normalized `[origin fact]` pair. This was flagged in my first review and remains unfixed. It's not reachable for typical facts (which are vectors of keywords/strings/numbers, never sets), but it is a latent correctness issue: the function cannot distinguish "a bare fact that happens to be a 2-element vector with a set as its first element" from "an already-normalized pair". A guard (e.g. checking that the second element of a candidate pair is not itself a set, or requiring facts to have at least one non-set element) would close it. Low priority — worth a comment in the code at minimum.

2. **The graph does not render error details** — *minor*. For limit-exceeded results, the decision node carries only `:result :deny` and `:reason :limit-exceeded`; the actual error data (limit, max, facts, iterations) is not in the graph. The explain map has it (`:error {:type :limit-exceeded :limit ...}`), but the graph drops it. For audit/debug purposes this is a small gap — a caller who wants to know *why* the limit was hit must read the explain map directly rather than the graph. Not blocking; worth noting in the docs or adding an `:error` node kind.

3. **The `arity-mismatches` function does not catch predicate mismatches** — *minor, design choice*. It only checks lengths, not predicates. A fact using `:user` and a policy using `:person` would not be caught by `check-arity` (the two predicates are different). This is arguably out of scope for the current design — catching predicate mismatches would require knowing which predicates are "expected" for each role, which isn't well-defined in a generic Datalog engine. But it means `check-arity` can miss typos where the wrong predicate name is used consistently (e.g. facts use `:user` but policies use `:person` — both consistent within their own context, so no mismatch is reported). A future enhancement could flag "predicates that appear in one role but not another" as a warning. Low priority.

### Minor / observations

- **The `:arity-check :warn` default adds warnings but does not deny** — this is a deliberate design choice (it avoids breaking existing tokens), but it means a mismatched reject check still silently never fires; the caller must inspect `:warnings` to know. An alternative would be to make `:error` the default, or at least document more prominently that warnings are not errors. The README does show how to throw on the warning (for no-policies) but doesn't do the same for arity mismatches.
- **The semi-naive fixpoint is tested against a naive oracle on the store, but not on derivations** — the `fixpoint-matches-naive-oracle` test checks that the final store matches a naive fixpoint on 400 random programs. It does not check that the recorded derivations (used by `:explain? :all`) match what re-firing every rule would produce. The CHANGELOG claims "each round still derives exactly what re-firing every rule would" and "so is every derivation `:explain? :all` records" — this seems well-tested but could be strengthened with a naive-oracle test on the derivations table too. Low priority; the store correctness is the critical property.
- **The CI workflow does not cache the babashka binary** — it uses `DeLaGuardo/setup-clojure@13.7.0` which installs both Clojure and bb, but there's no explicit caching of the bb binary or a matrix over Java versions. The JVM job pins Temurin 21; that's reasonable for a library targeting modern JVMs. Minor.
- **The `arity-mismatches` function uses `[:index i]` as a location key for policies without an id** — this is correct but slightly awkward (the location format varies by context: `{:block idx :in :facts}` vs `{:block idx :in :rule-head :id r1}` vs `{:block :authorizer :in :policy :index 0}`). Not a bug, just a design choice worth documenting in the function's docstring (which it does — but the format is not fully specified).
- **The explain's fact table does not include facts from policies that were evaluated but did not match** — this is correct behavior (non-matching policies have no evidence to show), but it means the graph won't show facts that a non-deciding policy would have matched. For audit purposes this is fine; for debugging "why didn't this policy fire?" it could be useful to include the evaluated-but-unmatched policies' query patterns in the explain (which they are — as `:policies` entries with `:result :no-match`), but not their would-be matches. Minor.
- **The `normalize-facts` edge case is still unfixed** — see Real finding 1 above.

## Suggestions for improvement

1. **Add a guard or comment to `normalize-facts`** documenting the misparse risk (a bare fact that is a 2-element vector with a set as its first element), or tighten the check so it cannot misfire. Low priority but cheap.
2. **Render error details in the graph for limit-exceeded results** — either add an `:error` node kind carrying the limit/max/facts/iterations, or document that the graph intentionally drops error details and callers should read the explain map directly. Cheap to do; improves auditability.
3. **Document the `:arity-check :warn` default more prominently** — e.g. in the README's "Limits fail closed" section or a new "Warnings" subsection, showing how to throw on warnings (as is done for no-policies). This closes the gap where a mismatched reject check silently never fires and the caller doesn't know.
4. **Consider adding a naive-oracle test on derivations** — extend `fixpoint-matches-naive-oracle` to also compare the recorded derivations table against what re-firing every rule would produce, at least for small programs. This strengthens confidence in `:explain? :all` output.
5. **Consider flagging predicates that appear in one role but not another** — e.g. a fact predicate that never appears in any check or policy (or vice versa) as a warning. This would catch typos where the wrong predicate name is used consistently within its own context. Low priority; arguably out of scope for `check-arity`'s current design.
6. **Add an end-to-end test that pipes `evaluate` → `graph` for the limit-exceeded explain with `:explain? :all`** — this is verified empirically but not pinned by a test; adding it would prevent regressions. Cheap.
7. **Consider caching the babashka binary in CI** — minor performance improvement; not blocking.
8. **Document the location format for `arity-mismatches` locations** — the docstring describes the shape but doesn't fully specify the per-context keys (`:id` vs `:index`, `:block` vs `:authorizer`). A short table would help consumers parse the output.

## Bottom line

The fixes are thorough and well-tested. Every finding from my first review is addressed — most importantly the happy-path graph crash (finding 2), the strict arity fix (finding 1), the env leak (finding 4), and the explain shape (finding 5) — plus several security-critical issues that went beyond what I flagged: the origin-hiding bug (0.2.0–0.13.0, critical), the 0.14.0 early-stop fix (high), and the semi-naive fixpoint with a predicate index (performance). The CI workflow runs on both JVM and babashka; the README, context.md, CHANGELOG.md and docs/TODO.md all describe the new behavior accurately.

The remaining items are polish: the `normalize-facts` edge case (still unfixed, not reachable in practice), error details dropped from the graph for limit-exceeded results, the `:arity-check :warn` default documented more prominently, and a few minor test/doc improvements. No correctness bugs were found in this pass; no security issues beyond what was already fixed remain open.

No coding was done for this review; nothing in the repo was modified except this review file.

---

## Open questions

- ~~Should `:arity-check` default to `:error` instead of `:warn`? The current default avoids breaking existing tokens but means a mismatched reject check silently never fires unless the caller inspects warnings. A stronger default would be safer for an authorization engine; a weaker one is more compatible.~~ → Decisions
- ~~Should the graph render error details (limit, max, facts, iterations) as an `:error` node kind? This would improve auditability but adds complexity to the renderer.~~ → Decisions
- ~~Should `check-arity` also flag predicates that appear in one role but not another (e.g. a fact predicate never used by any check or policy)? This would catch typos where the wrong predicate name is used consistently within its own context, but it's arguably out of scope for the current design.~~ → Decisions
- ~~Should `normalize-facts` be tightened to avoid misparsing bare facts that happen to look like normalized pairs? Low priority; not reachable in practice.~~ → Decisions

---

## Decisions

- 2026-11-22 — Read-only follow-up review at v0.15.0; no files changed except this review. Tests were run on both JVM and babashka (118 tests / 650 assertions, 0 failures each); every finding was reproduced empirically before being written down.
- 2026-11-24 — `:arity-check` defaults to `:error` (0.16.0, breaking): a mismatched reject check or deny policy is a fail-open, and `:error` denies with `:reason :arity-mismatch` rather than throwing, so the decision still depends only on the data; `:warn` / `:off` stay available.
- 2026-11-24 — The graph carries error details on the decision node (`:error`), not a new node kind: one node, nothing to traverse; plus an end-to-end `evaluate` → `graph` test for limit-exceeded with `:explain? :all` (suggestion 6).
- 2026-11-24 — No role-based predicate lint in `check-arity`: facts no check uses are normal, and "used but never produced" is often intended (a reject on `:revoked`); if ever, a separate opt-in lint.
- 2026-11-24 — `normalize-facts`: pass a pair through only when its second element is a vector, and say so in the docstring (a real fact starts with a predicate keyword, never a set).
- 2026-11-24 — Docs: specify `arity-mismatches` location keys; README shows treating warnings as errors (suggestions 3, 8). Pin the derivation oracle as a test (suggestion 4). Skip bb caching in CI (the job takes ~13 s; suggestion 7).
