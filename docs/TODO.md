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
- [ ] Semi-naive fixpoint — rules re-fire over every fact each round; a 400-step chain takes ~9 s (JVM) with or without explain, ~40 s on bb
- [x] CI — GitHub Actions running `clojure -X:test` on push/PR (`.github/workflows/test.yml`: JVM tests + JAR build, and `bb test:bb`)
- [x] `deps.edn` — remove the nonexistent `"resources"` path
- [x] Test `authorizer-with-signers` when the authorizer has no `:facts`
- [x] Document within-round block ordering — later blocks see earlier blocks' derived facts in the same round; README and architecture docs (README model + context.md; order can't change the fixpoint)
- [ ] Up-front arity validation for reject checks / deny policies — with strict matching, a reject pattern of the wrong arity silently never fires (fail open); see review open question
- [ ] Bump to 0.13.0 after the arity fix — strict arity is a behaviour change that can reject tokens that pass today; `CHANGELOG.md` is kept current with each commit
