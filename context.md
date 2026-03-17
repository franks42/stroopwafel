# Stroopwafel — Canonical Authorization Tokens for Clojure

## What This Is

Stroopwafel is a capability-based authorization token library for Clojure,
inspired by [Biscuit](https://github.com/eclipse-biscuit/biscuit) and derived
from [KEX](https://github.com/serefayar/kex).

**Name origin**: cookie → biscuit → kex (Swedish) → stroopwafel (Dutch).
Like a stroopwafel: two layers with something sealed between them — signed
blocks wrapping authorized data.

**Current version**: v0.8.0 (Requester-bound tokens)

## Goals

1. **Adopt canonical-edn (CEDN)** as the deterministic serialization layer,
   replacing KEX's ad-hoc canonicalization with `cedn/canonical-bytes` for
   all signing and verification. ✓ Done

2. **Achieve Biscuit feature parity** — the parts that matter for Clojure:
   - Append-only signed block chains (Ed25519) ✓ (from KEX)
   - Datalog authorization engine with proper scoping ✓ Done (v0.2.0)
   - Block isolation / attenuation (new blocks can only restrict, never expand) ✓ Done (v0.2.0)
   - Negative constraints (deny rules) ✓ Done (v0.2.0)
   - Revocation IDs ✓ Done (v0.3.0)
   - Authorizer policies (allow/deny) ✓ Done (v0.3.0)
   - Ephemeral keys per block ✓ Done (v0.3.0)
   - Token sealing ✓ Done (v0.4.0)
   - Datalog expressions (:when guards, :let bindings) ✓ Done (v0.5.0)
   - Third-party blocks ✓ Done (v0.6.0)

3. **Multi-platform** — JVM, Babashka, and potentially ClojureScript/nbb,
   following the same .cljc patterns as CEDN.

4. **Zero unnecessary deps** — Clojure + CEDN + JCA crypto only. ✓ Done

## Lineage

### From KEX (starting point)

KEX is a ~470-line proof-of-concept by Seref Ayar (EPL-1.0).
We copy and modify rather than fork because the changes are too fundamental
for upstream compatibility.

KEX provided the skeleton:
- `kex.core` → `stroopwafel.core` — public API
- `kex.datalog` → `stroopwafel.datalog` — Datalog engine
- `kex.block` → `stroopwafel.block` — block chain structure
- `kex.crypto` → `stroopwafel.crypto` — Ed25519, SHA-256, CEDN signing
- `kex.graph` → `stroopwafel.graph` — proof visualization

KEX limitations addressed:
- ~~No block isolation (delegated blocks can expand authority)~~ ✓ Fixed in v0.2.0
- ~~No negative constraints or deny rules~~ ✓ Fixed in v0.2.0
- ~~Ad-hoc canonicalization (not CEDN)~~ ✓ Fixed in v0.1.0
- ~~No revocation~~ ✓ Fixed in v0.3.0
- ~~No third-party blocks~~ ✓ Fixed in v0.6.0
- JVM-only

### From Biscuit (target feature set)

Reference repos (cloned locally for easy access):
- `../biscuit/` — specification (token format, Datalog semantics, crypto scheme)
- `../biscuit-java/` — Java implementation (closest to our platform)
- `../biscuit-rust/` — reference implementation
- `../biscuit-cli/` — CLI tool for generating/inspecting tokens

Key Biscuit spec areas:
- Token format: authority block + 0..n attenuation blocks, each signed
- Datalog: facts, rules, checks, policies; scoped per block
- Crypto: Ed25519 signature chain, public key attenuation
- Attenuation: each block can only restrict the authority, never expand
- Third-party blocks: signed by external keys, included in the chain
- Revocation: revocation IDs derived from block signatures

### From CEDN (serialization layer)

`com.github.franks42/cedn {:mvn/version "1.2.0"}` — deterministic EDN
serialization. Same value → same bytes on all platforms.
Replaces KEX's `kex.crypto/canonical` + `pr-str` with `cedn/canonical-bytes`.

CEDN 1.2.0 adds native byte array support via `#bytes "hex"` tagged literal,
which was specifically requested for stroopwafel's signing pipeline (SHA-256
hashes and Ed25519 signatures are byte arrays).

## Current Architecture (v0.8.0)

```
stroopwafel/
├── deps.edn
├── context.md                  ← this file
├── docs/
│   ├── biscuit-kex-analysis.md ← original research: Biscuit, KEX, and initial gap analysis
│   ├── biscuit-gap-analysis.md ← current gap status vs Biscuit spec
│   ├── bytes-support.md        ← CEDN #bytes feature request (implemented)
│   ├── datalog-expressions-clj-design.md ← expression design: :when, :let, built-ins
│   ├── stroopwafel-use-cases-examples.md ← 4 worked use cases with REPL snippets
│   ├── how-to-let-llms-use-your-credit-card-securely.md ← AI agent transaction security design
│   ├── spki-sdsi-vs-biscuit.md ← SPKI/SDSI vs Biscuit comparison (external contribution)
│   ├── spki-sdsi-vs-biscuit-concerns.md ← review concerns on the above
│   ├── spki-sdsi-vs-biscuit-gemini.md ← Gemini's take on SPKI vs Biscuit
│   └── spki-sdsi-vs-biscuit-gpt.md   ← GPT's take on SPKI vs Biscuit
├── src/
│   └── stroopwafel/
│       ├── core.clj            ← public API: new-keypair, issue, attenuate, seal, verify, evaluate, revocation-ids, graph, third-party-request, create-third-party-block, append-third-party
│       ├── block.clj           ← block chain signing and verification
│       ├── crypto.clj          ← Ed25519, SHA-256, key encode/decode, key predicates, CEDN canonical-bytes
│       ├── datalog.clj         ← Datalog engine with fact store, scoping, origin tracking, expressions, byte-array-aware unification
│       ├── graph.clj           ← explain tree → graph visualization
│       └── request.clj         ← signed requests for requester-bound tokens (proof-of-possession)
└── test/
    └── stroopwafel/
        ├── core_test.clj       ← 29 tests (e2e, revocation, policies, ephemeral, seal, expressions, third-party)
        ├── crypto_test.clj     ← 15 tests (crypto, key encode/decode, ephemeral chain)
        ├── datalog_test.clj    ← 39 tests (10 original + 9 scoping + 14 expressions + 6 third-party scope)
        ├── graph_test.clj      ← 5 tests
        └── request_test.clj    ← 8 tests (sign/verify round-trip, tampered, wrong-key, Datalog join integration)
```

96 tests, 183 assertions. clj-kondo clean, cljfmt clean.

## Dependencies

```clojure
{:paths ["src" "resources"]
 :deps {org.clojure/clojure {:mvn/version "1.12.4"}
        com.github.franks42/cedn {:mvn/version "1.2.0"}}}
```

Production deps: Clojure + CEDN only.
CEDN itself has zero transitive deps.

## Key Design Decisions

1. **CEDN over pr-str**: `encode-block` is a single call to
   `cedn/canonical-bytes` — no manual canonicalization, no prep step.
   Deterministic, spec-backed, cross-platform.

2. **#bytes tagged literal**: CEDN 1.2.0 natively serializes byte arrays as
   `#bytes "deadbeef"` (lowercase hex). Eliminates the need for manual
   byte-to-hex conversion before serialization.

3. **Set-based origin model**: Facts are tagged with origin sets rather than
   keyword labels. Authority facts get `#{0}`, block N facts get `#{N}`,
   authorizer facts get `#{:authorizer}`. Derived facts carry the union of
   their input origins plus the rule's block index. This enables precise
   scope filtering using `(subset? fact-origin trusted-origins)`.

4. **Scope isolation**: Each block only sees authority facts, its own facts,
   and authorizer facts. Block 0 checks: `#{0 :authorizer}`.
   Block N checks: `#{0 N :authorizer}`. Authorizer checks: `#{0 :authorizer}`.
   This is the core Biscuit security guarantee: delegated blocks can only
   restrict authority, never expand it.

5. **Fixpoint rule evaluation**: Rules fire repeatedly until no new facts are
   produced (or limits are reached: 100 iterations, 1000 facts). Previous
   KEX code only fired rules once, missing transitive derivations.

6. **Deny rules (reject-if)**: Checks with `:kind :reject` fail when the
   query matches (inverse of normal checks). Enables negative constraints
   like "reject if user is banned".

7. **Authorizer policies**: Ordered allow/deny policies evaluated after all
   checks pass. First matching policy wins. No match = deny (closed-world).
   Distinct from checks — policies determine the final authorization decision.

8. **Revocation IDs**: SHA-256 of each block's signature bytes, returned as
   hex strings. Applications maintain revocation sets/bloom filters externally.

9. **Ephemeral keys per block**: Each attenuation block gets a fresh Ed25519
   keypair. Block i is verified with block i-1's `:next-key`. Token format:
   `{:blocks [...] :proof eph-sk}`. Whoever holds the token can attenuate —
   the attenuation guarantee is enforced by both Datalog scoping AND crypto.

10. **Sealed tokens**: `seal` signs the last block's hash with the ephemeral
    key, then discards it. Proof becomes `{:type :sealed :sig <bytes>}`.
    No encryption — pure signing + key destruction. Reversible sealing
    deliberately not supported (no realistic use case).

11. **Clojure-native expressions**: Instead of Biscuit's custom expression
    syntax, guards use Clojure forms evaluated by a mini-interpreter with
    whitelisted built-in functions (~35). `:when` clauses filter after pattern
    matching; `:let` bindings compute intermediate values. No `eval`, no
    `resolve`, no namespace lookup — security boundary enforced by a closed
    function registry. See `docs/datalog-expressions-clj-design.md`.

12. **Third-party blocks**: External parties sign blocks that get appended to
    tokens without seeing the full token. Dual signature: the third party's
    external signature (binding content to a specific token via `previous-sig`)
    + the token holder's ephemeral key chain signature. The authorizer decides
    which external keys to trust via `:trusted-external-keys`. Trusted
    third-party block facts become visible to authorizer rules, checks, and
    policies — but NOT to other first-party blocks (per-block scope unchanged).

## Authorizer API

The `evaluate` function accepts an `:authorizer` keyword argument:

```clojure
(stroopwafel.core/evaluate token
  :authorizer {:facts    [[:time (System/currentTimeMillis)]
                           [:resource "/api/data"]]
               :checks   [{:id    :check-read
                            :query [[:can "alice" :read "/api/data"]]}]
               :rules    '[{:id   :can-from-right
                            :head [:can ?u ?a ?r]
                            :body [[:right ?u ?a ?r]]}]
               :policies [{:kind :allow
                            :query [[:can "alice" :read "/api/data"]]}
                           {:kind :deny
                            :query [[:user "mallory"]]}]})
```

Authorizer facts/rules/checks/policies are evaluated with scope
`#{0 :authorizer}` — they see authority block facts but not delegated block
facts.

## Revocation API

```clojure
(stroopwafel.core/revocation-ids token)
;; => ["a1b2c3..." "d4e5f6..."]  ; one hex string per block
```

Each ID is the SHA-256 hash of the block's Ed25519 signature. Revoking any
block's ID invalidates the token (append-only chain means revoking an earlier
block invalidates all subsequent blocks).

## Seal API

```clojure
(def sealed (stroopwafel.core/seal token))
;; => {:blocks [...] :proof {:type :sealed :sig <bytes>}}

(stroopwafel.core/sealed? sealed)  ;; => true
(stroopwafel.core/verify sealed {:public-key root-pk})  ;; => true
(stroopwafel.core/attenuate sealed {...})  ;; => throws
```

Sealing is irreversible by design. If you need to attenuate later, keep the
unsealed token.

## Expression API

Rules, checks, and policies support `:when` guard clauses and `:let` computed
bindings. Guards are Clojure forms evaluated by a whitelisted mini-interpreter
— no `eval`, no namespace resolution.

```clojure
;; Time-based token expiry
(stroopwafel.core/issue
  {:facts  [[:right "alice" :read "/data"]]
   :checks '[{:id    :check-expiry
              :query [[:time ?t]]
              :when  [(< ?t 1709251200000)]}]}  ;; expires March 2024
  {:private-key root-sk})

;; Authorizer provides current time + policy with guard
(stroopwafel.core/evaluate token
  :authorizer {:facts    [[:time (System/currentTimeMillis)]]
               :policies '[{:kind  :allow
                            :query [[:right ?u :read ?r] [:amount ?a]]
                            :when  [(<= ?a 100)]}]})

;; Rule with :let computed binding
'{:id   :compute-total
  :head [:invoice-total ?item ?total]
  :body [[:line-item ?item ?qty ?price]]
  :let  [[?total (* ?qty ?price)]]
  :when [(> ?total 0)]}
```

Available built-in functions (~35): `<` `>` `<=` `>=` `=` `not=` `+` `-` `*`
`/` `mod` `rem` `str/starts-with?` `str/ends-with?` `str/includes?`
`str/lower-case` `str/upper-case` `subs` `str` `not` `and` `or` `contains?`
`empty?` `count` `string?` `number?` `keyword?` `int?` `nil?` `some?`
`re-matches` `re-find`.

Evaluation order: `eval-body` (pattern match) -> `eval-let` (compute bindings)
-> `eval-when` (filter by guards) -> `instantiate` (produce head).

See `docs/datalog-expressions-clj-design.md` for full design document.

## Third-Party Block API

Third-party blocks let an external party (e.g., an IdP) sign a block that gets
appended to a token — without seeing the full token. The block content is bound
to a specific token instance via `previous-sig`.

```clojure
;; 1. Token holder creates request
(def request (stroopwafel.core/third-party-request token))
;; => {:previous-sig <bytes>}

;; 2. Third party signs block (on their side)
(def tp-block
  (stroopwafel.core/create-third-party-block
    request
    {:facts [[:email "alice" "alice@idp.com"]]}
    {:private-key idp-sk :public-key idp-pk}))
;; => {:facts [...] :external-sig <bytes> :external-key <bytes>}

;; 3. Token holder appends
(def token2 (stroopwafel.core/append-third-party token tp-block))

;; 4. Authorizer trusts specific external keys
(stroopwafel.core/evaluate token2
  :authorizer {:trusted-external-keys [idp-pk]
               :checks [{:id    :has-email
                          :query [[:email "alice" "alice@idp.com"]]}]})
```

Scope rules: Trusted third-party block facts are visible to the authorizer's
rules, checks, and policies. First-party blocks still cannot see third-party
facts (per-block scope unchanged). Without `:trusted-external-keys`, third-party
facts are invisible to the authorizer (backward compatible).

## Biscuit Parity Status

| Feature | Biscuit | Stroopwafel v0.8.0 | Gap |
|---------|---------|-------------------|-----|
| Ed25519 signatures | Yes | ✓ | — |
| Block chain | Yes | ✓ | — |
| Block isolation | Yes | ✓ | — |
| Deny rules | Yes | ✓ | — |
| Authorizer context | Yes | ✓ | — |
| Authorizer policies | Yes | ✓ | — |
| Scoped + fixpoint rules | Yes | ✓ | — |
| Revocation IDs | Yes | ✓ | — |
| Ephemeral keys | Yes | ✓ | — |
| Sealed tokens | Yes | ✓ | — |
| Datalog expressions | Yes | ✓ | — (Clojure-native :when/:let) |
| Canonical serialization | Protobuf | ✓ CEDN | Different wire format |
| Proof visualization | No | ✓ | Stroopwafel-only feature |
| Third-party blocks | Yes | ✓ | — |
| Requester-bound tokens | No (bearer only) | ✓ | Stroopwafel-only — SPKI model |
| Cross-platform | Multi-lang | ✓ JVM + Babashka | CLJS remains Phase 4 |

## Current Work Direction (as of v0.8.0)

With Biscuit feature parity achieved, the focus has shifted to:

### Applied Use Cases & Documentation
- **Use cases doc** (`docs/stroopwafel-use-cases-examples.md`): 4 worked examples:
  1. API gateway chain (attenuation, time-limited, sealed)
  2. IoT device provisioning (factory → fleet → device hierarchy)
  3. Cross-org federation with third-party blocks
  4. Capability-gated nREPL (middleware injection, namespace/op restrictions)
- **SPKI/SDSI comparison** (`docs/spki-sdsi-vs-biscuit.md`): deep comparison of
  SPKI's distributed certificates vs Biscuit's centralized authorizer model.
  Review concerns saved separately.

### AI Agent Transaction Security
- **Design doc** (`docs/how-to-let-llms-use-your-credit-card-securely.md`): 1400+ lines
- Architecture: separation of intent (AI realm) from execution (deterministic realm)
- Panel-of-judges: heterogeneous LLMs evaluate structured intents against user policy
- Capability tokens as the cryptographic bridge between realms
- **Agent authentication via signed requests** (not bearer tokens):
  - Token carries `[:authorized-agent-key agent-pk]` — bound to specific agent
  - Agent signs each request with its private key
  - Execution service verifies request signature against token's agent key
  - Datalog join: `[:authorized-agent-key ?k]` ∧ `[:request-verified-agent-key ?k]`
  - One round trip, no separate authN protocol
  - This is the SPKI model (subject-key binding) expressed as Datalog facts
- **Holder binding landscape**: Biscuit is bearer-only (no PoP mechanism).
  Industry trajectory: OAuth bearer → DPoP/mTLS patches → GNAP key-bound-by-default.
  SPKI/SDSI had key-bound authorization in 1996.
- Prior art survey: ISACA, CSA, OWASP, NIST, Visa TAP, ERC-8004, AgentSpec, ABC
- 10 known gaps with severity ratings and mitigations
- Next step: MCP tool server prototype with Stroopwafel capability gates

### Bug Fix (in this cycle)
- `datalog.clj:73` `trusted-origins` — `(pos? :authorizer)` ClassCastException
  when authorizer rules provided without `:trusted-external-keys`. Fixed by
  changing guard to `(number? block-index)`.

## Reference Repos (local)

| Repo | Path | What to look at |
|------|------|-----------------|
| KEX | `../kex/` | Starting point source code |
| CEDN | `../canonical-edn/` | Serialization library (our dep) |
| Biscuit spec | `../biscuit/` | Token format, Datalog semantics, crypto |
| Biscuit Java | `../biscuit-java/` | JVM implementation patterns |
| Biscuit Rust | `../biscuit-rust/` | Reference implementation |
| Biscuit CLI | `../biscuit-cli/` | Token inspection/generation |

## Implementation Phases

### Phase 1: Foundation ✓ (v0.1.0)
- ✓ Copy KEX source into repo
- ✓ Replace `kex.crypto/canonical` + `pr-str` with CEDN `canonical-bytes`
- ✓ Get existing KEX tests passing (27/27)
- ✓ Add CEDN as a Maven dependency (1.2.0 with #bytes support)
- ✓ Lint clean (clj-kondo + cljfmt, zero warnings)

### Phase 2: Block Isolation & Attenuation ✓ (v0.2.0)
- ✓ Rename `kex.*` → `stroopwafel.*` namespaces
- ✓ Fact store with set-based origin tracking
- ✓ Scope filtering (trusted-origins, visible?, facts-for-scope)
- ✓ Origin-aware unification and eval-body
- ✓ Scoped rule firing with fixpoint iteration
- ✓ Restructured eval-token with per-block isolation
- ✓ Deny rules (reject-if) support
- ✓ Authorizer context API (:authorizer kwarg on evaluate)
- ✓ Graph dispatch updated for set-based origins
- ✓ 9 new scoping tests + 2 end-to-end tests (38 total, 71 assertions)

### Phase 3a: Easy Wins ✓ (v0.3.0)
- ✓ Revocation IDs (SHA-256 of block signatures, hex strings)
- ✓ Authorizer policies (ordered allow/deny, first match wins, closed-world)
- ✓ 10 new tests (4 revocation ID + 6 policy)

### Phase 3b: Ephemeral Keys ✓ (v0.3.0)
- ✓ Fresh Ed25519 keypair per attenuation block
- ✓ Ephemeral key threading in verify-chain
- ✓ Token format: `{:blocks [...] :proof eph-sk}`
- ✓ Attenuate uses token proof — no explicit key needed
- ✓ Public key encode/decode (X.509) in crypto.clj
- ✓ 5 new tests (ephemeral uniqueness, forged block rejection, chain verify)

### Phase 3c: Sealed Tokens ✓ (v0.4.0)
- ✓ `seal` signs last block hash with ephemeral key, discards key
- ✓ `sealed?` predicate, `attenuate` throws on sealed tokens
- ✓ `verify` validates seal signature against last block's next-key
- ✓ No encryption needed — pure signing + key destruction
- ✓ Reversible sealing deliberately not supported (no realistic use case)
- ✓ 5 new tests (seal-verifies, rejects-attenuate, evaluates-same, double-seal, chain)

### Phase 3d: Datalog Expressions ✓ (v0.5.0)
- ✓ `:when` guard clauses on rules, checks, and policies
- ✓ `:let` bindings for computed variables
- ✓ Mini-interpreter with whitelisted built-in functions (~35)
- ✓ Clojure-native forms — no custom parser needed
- ✓ Backward compatible — existing rules/checks/policies unchanged
- ✓ 18 new tests (14 datalog + 4 e2e)
- ✓ Design document: `docs/datalog-expressions-clj-design.md`

### Phase 3e: Third-Party Blocks ✓ (v0.6.0)
- ✓ `third-party-request` — extract request from token for external party
- ✓ `create-third-party-block` — third party signs block bound to specific token
- ✓ `append-third-party` — token holder appends signed block to chain
- ✓ Dual signature: external-sig (third party) + chain sig (token holder)
- ✓ Replay prevention via `previous-sig` binding
- ✓ `verify-chain` validates external signatures
- ✓ Authorizer trusts specific keys via `:trusted-external-keys`
- ✓ Scope: authorizer sees trusted third-party facts; first-party blocks do not
- ✓ 12 new tests (6 datalog scope + 6 e2e)

### Phase 4a: Babashka Compatibility ✓ (v0.7.0)
- ✓ Removed `java.security.PrivateKey`/`PublicKey` type hints (not in bb's class allowlist)
- ✓ Added `ed25519-private-key?` and `ed25519-public-key?` predicates (work on JVM + bb)
- ✓ All 88 tests pass on both JVM (Clojure 1.12.4) and Babashka (v1.12.217)
- ✓ No .cljc conversion needed — bb loads .clj files directly
- ✓ Full JDK crypto (Ed25519, SHA-256, X.509) available in bb via GraalVM

### Phase 5: Requester-Bound Tokens ✓ (v0.8.0)
- ✓ `stroopwafel.request/sign-request` — agent signs request body with Ed25519
- ✓ `stroopwafel.request/verify-request` — verify signature, return agent-key bytes
- ✓ Datalog join pattern: `[:authorized-agent-key ?k]` ∧ `[:request-verified-agent-key ?k]`
- ✓ Fixed `eval-body` env threading bug — patterns now share bindings through unification
- ✓ Added `value=` for byte-array-aware equality in Datalog `bind` and `unify*`
- ✓ 8 new tests (4 sign/verify + 4 integration with Datalog join)
- ✓ 96 tests, 183 assertions pass on both JVM and Babashka
- ✓ README.md rewritten with full feature overview and requester-bound explanation

### Phase 6: ClojureScript
- .cljc throughout (potentially CLJS/nbb)
- Cross-platform crypto abstraction (JCA on JVM/bb, Web Crypto API on JS)

## License

EPL-2.0 (CEDN license). KEX attribution preserved per EPL-1.0.
