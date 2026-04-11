# Library Separation Plan: Four Clean Layers

> Every library does one thing. Crypto doesn't know about logic.
> Logic doesn't know about crypto. The PDP wires them together.
> The PEP enforces the result in its wire format.

---

## The Four Libraries

```
┌─────────────────────────────────────────────────────────┐
│  Application PEP (alpaca-clj, websocket-app, etc.)      │
│  Enforces decisions in the app's wire format             │
│  Depends on: stroopwafel-pdp + app-specific deps         │
├─────────────────────────────────────────────────────────┤
│  stroopwafel-pdp                                         │
│  Assembles verified facts, calls engine, returns decision│
│  Depends on: signet + stroopwafel                        │
├──────────────────────┬──────────────────────────────────┤
│  signet              │  stroopwafel                      │
│  Crypto primitives   │  Datalog engine                   │
│  Sign, verify, keys  │  Facts, rules, joins, decide      │
│  Depends on:         │  Depends on:                      │
│  cedn, uuidv7        │  NOTHING (zero deps)              │
└──────────────────────┴──────────────────────────────────┘
```

---

## What Each Library Contains

### stroopwafel — Pure Assertions-DL Engine

**Zero external dependencies.** Only `clojure.set` and `clojure.string`.

| File | What it does |
|---|---|
| `datalog.clj` | Unification, rule firing, fixpoint, scope isolation, checks, policies (594 lines) |
| `core.clj` | `evaluate` — the single public entry point |
| `graph.clj` | Explain tree → graph visualization |

That's it. ~700 lines total. Receives facts as plain vectors,
returns `{:valid? true/false}`. Knows nothing about signatures,
keys, tokens, envelopes, HTTP, or any wire format.

**Public API:**
```clojure
(stroopwafel.core/evaluate
  {:blocks [{:facts [...] :rules [...] :checks [...]}]}
  :authorizer {:facts [...] :rules [...] :policies [...]}
  :explain? true)
;; → {:valid? true/false :explain ...}
```

### signet — Crypto Primitives

**Depends on:** cedn, uuidv7

| File | What it does |
|---|---|
| `key.cljc` | Key records, multimethods, store, URN kid, Ed↔X conversion |
| `sign.cljc` | Ed25519 sign/verify, EDN envelopes |
| `chain.cljc` | Capability block chains — extend, close, verify |
| `encoding.cljc` | Base64url |
| `impl/jvm.clj` | JCA backend |

Knows nothing about authorization, Datalog, policies, or
decisions. Signs things, verifies things, builds chains.

**Public API:**
```clojure
(signet.key/signing-keypair)                    ;; generate
(signet.sign/sign-edn keypair payload)          ;; sign
(signet.sign/verify-edn envelope)               ;; verify
(signet.chain/extend token content)             ;; build chain
(signet.chain/close token)                      ;; seal
(signet.chain/verify token)                     ;; verify chain
```

### stroopwafel-pdp — The Decision Assembly Point

**Depends on:** signet, stroopwafel

| File | What it does |
|---|---|
| `pdp.clj` | Context accumulator: add-token, add-facts, decide |
| `trust.clj` | Trust-root fact generation (from current stroopwafel.trust) |
| `replay.clj` | UUIDv7 freshness + nonce checking (from current stroopwafel.replay) |
| `pipeline.clj` | Generic verify → extract → evaluate flow |

The bridge: takes signed artifacts (signet), verifies them,
extracts facts, calls the engine (stroopwafel), returns a
decision.

**Public API:**
```clojure
(require '[stroopwafel-pdp.pdp :as pdp])

(-> (pdp/context)
    (pdp/add-token signed-chain {:trust-root root-pk})
    (pdp/add-signed-request envelope)
    (pdp/add-facts [[:current-time (System/currentTimeMillis)]
                    [:requested-effect :read]
                    [:requested-domain "market"]])
    (pdp/decide
      :rules [...]
      :policies [{:kind :allow :query [...]}]))
;; → {:allowed? true/false}
```

### Application PEP (e.g., alpaca-clj)

**Depends on:** stroopwafel-pdp + app-specific deps

Wire-format-specific enforcement:

```clojure
;; HTTP PEP (alpaca-clj)
(defn wrap-auth [handler]
  (fn [req]
    (let [token    (extract-bearer req)
          sig-meta (extract-signature req)
          decision (-> (pdp/context)
                       (pdp/add-token token {:trust-root root-pk})
                       (pdp/add-signed-request sig-meta)
                       (pdp/add-facts (canonicalize req))
                       (pdp/decide :policies [...]))]
      (if (:allowed? decision)
        (handler req)
        {:status 403 :body "Denied"}))))
```

---

## Migration Plan

### Phase 1: Strip stroopwafel to pure logic

**Remove from stroopwafel:**
- `crypto.clj` → already in signet as `impl/jvm.clj`
- `envelope.clj` → already in signet as `sign.cljc`
- `block.clj` → already in signet as `chain.cljc`
- `core.clj` functions: `issue`, `attenuate`, `seal`, `verify`,
  `new-keypair`, `third-party-request`, `create-third-party-block`,
  `append-third-party`, `revocation-ids` → move to signet or
  stroopwafel-pdp
- `ssh.clj` → moves to signet (Phase 3)
- `replay.clj` → moves to stroopwafel-pdp
- `trust.clj` → moves to stroopwafel-pdp
- `pep.clj` → moves to application layer
- `authorize.clj` → splits: pure accumulator stays or moves to
  stroopwafel-pdp, crypto parts (add-token verify) move to
  stroopwafel-pdp
- `request.clj` → moves to signet

**What remains in stroopwafel:**
- `datalog.clj` — the engine (unchanged)
- `core.clj` — just `evaluate` wrapping `eval-token`
- `graph.clj` — explain visualization (pure data)

### Phase 2: Rewrite stroopwafel tests

- All tests use bare `{:blocks [{:facts [...] ...}]}` — no crypto
- `datalog_test.clj` — already pure, minimal changes
- `core_test.clj` — rewrite: hand-built token structures, no
  `sw/issue`, no `sw/seal`, no `sw/verify`
- `graph_test.clj` — already pure
- Remove: `crypto_test.clj`, `envelope_test.clj`,
  `request_test.clj`, `ssh_test.clj`, `replay_test.clj`,
  `pep_test.clj`, `trust_test.clj`
- Run tests — all must pass with zero crypto deps

### Phase 3: Create stroopwafel-pdp

- New repo/library
- Move `trust.clj`, `replay.clj` from stroopwafel
- Create `pdp.clj` — context accumulator + decide
  (from `authorize.clj`, with signet verify calls)
- Create `pipeline.clj` — generic verify → extract → evaluate
- Integration tests: full pipeline with real signet signing +
  stroopwafel evaluation
- Depends on: signet + stroopwafel

### Phase 4: Update signet

- Ensure `signet.chain` covers what `stroopwafel.block` did
- Move `core.clj` token operations (`issue`, `attenuate`, `seal`,
  `verify`, `revocation-ids`) into signet chain API
- Move third-party block operations
- Move `request.clj` (signed requests)
- Integration tests for chain operations

### Phase 5: Update alpaca-clj

- Depend on stroopwafel-pdp (which pulls in signet + stroopwafel)
- `auth.clj` uses `pdp/context → add-token → decide`
- `client_pep.clj` uses same pattern for outbound checks
- PEP stays in alpaca-clj (Ring middleware, HTTP-specific)
- Run all 110 tests

### Phase 6: Clean up and tag

- Remove migrated code from stroopwafel
- Update all docs, context.md, plan.md
- Lint all repos
- Tag: stroopwafel v1.0.0 (pure engine), signet v0.2.0,
  stroopwafel-pdp v0.1.0, alpaca-clj v0.8.0

---

## Verification at Each Phase

| Phase | Test command | Expected |
|---|---|---|
| 1-2 | `clojure -X:test` in stroopwafel | All logic tests pass, zero deps |
| 3 | `clojure -X:test` in stroopwafel-pdp | Integration tests pass |
| 4 | `clojure -X:test` in signet | 43+ tests pass |
| 5 | `bb test` in alpaca-clj | 110 tests pass |
| 6 | All repos lint clean, all tests green | Ready to tag |

---

## Resulting Dependency Graph

```
alpaca-clj
  └── stroopwafel-pdp
        ├── signet
        │     ├── cedn
        │     └── uuidv7
        └── stroopwafel  (ZERO deps)
```

Each layer depends only downward. No cycles. The bottom layer
(stroopwafel) has zero dependencies and can be embedded anywhere.

---

*Document status: implementation plan.*
*Date: April 2026.*
