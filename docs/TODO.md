# TODO

From `docs/review-swival-inkling-2-mini.md` (revised 2026-11-23), in priority order.

## Code fixes

- [x] Strict arity in `unify*` — require `(= (count pattern) (count fact))` (datalog.clj:130); finding 1, authorization bypass
- [x] Arity regression tests — check, rule body, allow policy (the three reproduced cases), plus a reject check
- [x] Drop `:env` from `eval-expr` ex-data (datalog.clj:266) — finding 4; audit other `ex-info` sites for the same leak (graph.clj "Unknown explain node shape" also fixed; limit errors carry only config/counts)
- [x] ~~Map-shaped `:because` in `eval-check` — always `{:origin … :fact …}` (datalog.clj:498); finding 2~~ superseded by rule proofs below; finding 2 fixed there
- [x] `graph` handles the limit-exceeded explain — error node or a clear error, not "Unknown explain node shape"; finding 3 (explain is now a decision with `:reason :limit-exceeded`; graph renders a single decision node)
- [x] End-to-end `evaluate` → `graph` tests — README example, limit-exceeded, reject-pass check, token with no checks (all done, plus derived-fact, join, shared-fact, reject-fail, cycles, policies)
- [x] Explain shows the full decision — every check result, the deciding policy (id, kind, bindings), non-nil when there are no checks (datalog.clj:660–676); finding 5
- [x] Rule proofs in explain — thread `:proof` through, or remove the unreachable derived-fact branch in `graph.clj`; decided: option A, see review Decisions
- [x] All-reasons explain (`:explain? :all`) — every derivation per fact, flat table, derivation cap; decided: show circular reasons, one flat shape for both modes
- [x] Keep every minimal origin set per fact — finding 6, critical: an appended block could hide authorizer facts (revoked token became valid); `docs/security-advisory-2026-11-23-origin-hiding.md`
- [x] Release 0.14.0 with the origin fix — bump, tag, deploy to Clojars; 0.12.0 and 0.13.0 are affected (tagged v0.14.0; Clojars deploy is Frank's)
- [x] Fixpoint ended early on an origin replacement (0.14.0, fail-open) — fixed on `fix/fixpoint-termination`: stop only when the store is unchanged; advisory addendum; release 0.14.1 (tagged v0.14.1; Clojars deploy is Frank's)
- [x] Semi-naive fixpoint — rules re-fire over every fact each round; a 400-step chain takes ~9 s (JVM) with or without explain, ~40 s on bb (now 167 ms on the JVM; checked against a naive oracle on 400 random programs; release 0.14.2: tagged v0.14.2; Clojars deploy is Frank's)
- [x] CI — GitHub Actions running `clojure -X:test` on push/PR (`.github/workflows/test.yml`: JVM tests + JAR build, and `bb test:bb`)
- [x] `deps.edn` — remove the nonexistent `"resources"` path
- [x] Test `authorizer-with-signers` when the authorizer has no `:facts`
- [x] Document within-round block ordering — later blocks see earlier blocks' derived facts in the same round; README and architecture docs (README model + context.md; order can't change the fixpoint)
- [x] Up-front arity validation for reject checks / deny policies — with strict matching, a reject pattern of the wrong arity silently never fires (fail open); `sw/check-arity` + `evaluate :arity-check :warn|:error|:off` (see review Decisions)
- [x] ~~No policies throws — `evaluate`/`eval-token` throw `:stroopwafel/error :no-policies` when `:policies` is missing/empty or `:authorizer` is absent; drop the `:no-policies` decision reason; checks-only tests use `{:kind :allow :query []}`; see review Decisions; 0.15.0~~ superseded by the next item
- [x] No policies denies — `:reason :no-policies` and a `{:type :no-policies}` warning, no throw; checks-only callers use `{:kind :allow :query []}`; see review Decisions; 0.15.0
- [x] Unknown keyword arguments to `evaluate` throw — a typo (`:authoriser`) silently dropped the authorizer and its deny policies; 0.15.0 (authorizer keys too: `:check` dropped checks)
- [x] Release 0.15.0 — breaking: no policies denies (with a warning); unknown options and authorizer keys throw (tagged v0.15.0; Clojars deploy is Frank's)
- [x] stroopwafel-pdp: pass the engine's `:warnings` through (it returns only `:allowed?`, `:error`, `:explain`), so its callers see `:no-policies`; review the `(or policies [])` fallback (`pdp/core.clj:173`, `spki/core.clj:326`) and tests that omit policies, which will now deny — separate repo, after 0.15.0 (on pdp branch `feat/stroopwafel-0.15`: dep 0.12.0 → 0.15.0, warnings passed through, `decide` options validated; fallback kept, it now denies; no test omitted policies)
- [ ] stroopwafel-pdp: default `:test` alias can't resolve `signet 0.3.1` (not on Clojars or in `~/.m2`); only `-M:test:dev` (local checkouts) builds — deploy signet 0.3.1, or pin a published version
- [x] Bump to 0.13.0 after the arity fix — strict arity is a behaviour change that can reject tokens that pass today; `CHANGELOG.md` is kept current with each commit
