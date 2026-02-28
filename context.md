# Stroopwafel — Canonical Authorization Tokens for Clojure

## What This Is

Stroopwafel is a capability-based authorization token library for Clojure,
inspired by [Biscuit](https://github.com/eclipse-biscuit/biscuit) and derived
from [KEX](https://github.com/serefayar/kex).

**Name origin**: cookie → biscuit → kex (Swedish) → stroopwafel (Dutch).
Like a stroopwafel: two layers with something sealed between them — signed
blocks wrapping authorized data.

**Current version**: v0.5.0 (Phase 3d — Datalog expressions)

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
   - Third-party blocks

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
- No third-party blocks
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

## Current Architecture (v0.5.0)

```
stroopwafel/
├── deps.edn
├── context.md                  ← this file
├── docs/
│   ├── biscuit-kex-analysis.md ← original research: Biscuit, KEX, and initial gap analysis
│   ├── biscuit-gap-analysis.md ← current gap status vs Biscuit spec
│   ├── bytes-support.md        ← CEDN #bytes feature request (implemented)
│   └── datalog-expressions-clj-design.md ← expression design: :when, :let, built-ins
├── src/
│   └── stroopwafel/
│       ├── core.clj            ← public API: new-keypair, issue, attenuate, seal, verify, evaluate, revocation-ids, graph
│       ├── block.clj           ← block chain signing and verification
│       ├── crypto.clj          ← Ed25519, SHA-256, key encode/decode, CEDN canonical-bytes
│       ├── datalog.clj         ← Datalog engine with fact store, scoping, origin tracking, expressions
│       └── graph.clj           ← explain tree → graph visualization
└── test/
    └── stroopwafel/
        ├── core_test.clj       ← 23 tests (e2e, revocation, policies, ephemeral, seal, expressions)
        ├── crypto_test.clj     ← 15 tests (crypto, key encode/decode, ephemeral chain)
        ├── datalog_test.clj    ← 33 tests (10 original + 9 scoping + 14 expressions)
        └── graph_test.clj      ← 5 tests
```

76 tests, 150 assertions. clj-kondo clean, cljfmt clean.

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

## Biscuit Parity Status

| Feature | Biscuit | Stroopwafel v0.5.0 | Gap |
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
| Third-party blocks | Yes | No | Medium — advanced pattern |
| Cross-platform | Multi-lang | JVM only | Phase 4 (bb ready) |

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

### Phase 3e: Remaining Parity
1. **Third-party blocks** — external parties sign blocks for delegated
   attestation. Advanced pattern, lower priority.

### Phase 4: Multi-platform
- .cljc throughout (JVM + Babashka + potentially CLJS)
- Cross-platform crypto (JCA on JVM, Web Crypto API on JS)
- Babashka already confirmed working (full JDK crypto in bb v1.12.215)

## License

EPL-2.0 (CEDN license). KEX attribution preserved per EPL-1.0.
