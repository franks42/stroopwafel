# TODO

From `docs/review-swival-inkling-2-mini.md` (revised 2026-11-23), in priority order.

## Code fixes

- [x] Strict arity in `unify*` — require `(= (count pattern) (count fact))` (datalog.clj:130); finding 1, authorization bypass
- [x] Arity regression tests — check, rule body, allow policy (the three reproduced cases), plus a reject check
- [x] Drop `:env` from `eval-expr` ex-data (datalog.clj:266) — finding 4; audit other `ex-info` sites for the same leak (graph.clj "Unknown explain node shape" also fixed; limit errors carry only config/counts)
- [ ] Map-shaped `:because` in `eval-check` — always `{:origin … :fact …}` (datalog.clj:498); finding 2
- [ ] `graph` handles the limit-exceeded explain — error node or a clear error, not "Unknown explain node shape"; finding 3
- [ ] End-to-end `evaluate` → `graph` tests — README example, limit-exceeded, reject-pass check, token with no checks
- [ ] Explain shows the full decision — every check result, the deciding policy (id, kind, bindings), non-nil when there are no checks (datalog.clj:660–676); finding 5
- [ ] Rule proofs in explain — thread `:proof` through, or remove the unreachable derived-fact branch in `graph.clj`; waiting on open question
- [ ] CI — GitHub Actions running `clojure -X:test` on push/PR
- [ ] `deps.edn` — remove the nonexistent `"resources"` path
- [ ] Test `authorizer-with-signers` when the authorizer has no `:facts`
- [ ] Document within-round block ordering — later blocks see earlier blocks' derived facts in the same round; README and architecture docs
- [ ] Up-front arity validation for reject checks / deny policies — with strict matching, a reject pattern of the wrong arity silently never fires (fail open); see review open question
- [ ] Bump to 0.13.0 + changelog after the arity fix — strict arity is a behaviour change that can reject tokens that pass today
