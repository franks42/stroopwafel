# Stroopwafel — Canonical Authorization Tokens for Clojure

## What This Is

Stroopwafel is a capability-based authorization token library for Clojure,
inspired by [Biscuit](https://github.com/eclipse-biscuit/biscuit) and derived
from [KEX](https://github.com/serefayar/kex).

**Name origin**: cookie → biscuit → kex (Swedish) → stroopwafel (Dutch).
Like a stroopwafel: two layers with something sealed between them — signed
blocks wrapping authorized data.

**Current version**: v0.2.0 (Phase 2 complete)

## Goals

1. **Adopt canonical-edn (CEDN)** as the deterministic serialization layer,
   replacing KEX's ad-hoc canonicalization with `cedn/canonical-bytes` for
   all signing and verification. ✓ Done

2. **Achieve Biscuit feature parity** — the parts that matter for Clojure:
   - Append-only signed block chains (Ed25519) ✓ (from KEX)
   - Datalog authorization engine with proper scoping ✓ Done (v0.2.0)
   - Block isolation / attenuation (new blocks can only restrict, never expand) ✓ Done (v0.2.0)
   - Negative constraints (deny rules) ✓ Done (v0.2.0)
   - Third-party blocks
   - Revocation support
   - Token sealing

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
- No revocation
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

## Current Architecture (v0.2.0)

```
stroopwafel/
├── deps.edn
├── context.md                  ← this file
├── docs/
│   ├── biscuit-kex-analysis.md ← detailed analysis of Biscuit, KEX, and gaps
│   └── bytes-support.md        ← CEDN #bytes feature request (implemented)
├── src/
│   └── stroopwafel/
│       ├── core.clj            ← public API: new-keypair, issue, attenuate, verify, evaluate, graph
│       ├── block.clj           ← block chain signing and verification
│       ├── crypto.clj          ← Ed25519, SHA-256, CEDN canonical-bytes
│       ├── datalog.clj         ← Datalog engine with fact store, scoping, origin tracking
│       └── graph.clj           ← explain tree → graph visualization
└── test/
    └── stroopwafel/
        ├── core_test.clj       ← 2 tests (end-to-end with authorizer)
        ├── crypto_test.clj     ← 12 tests
        ├── datalog_test.clj    ← 19 tests (10 original + 9 scoping)
        └── graph_test.clj      ← 5 tests
```

38 tests, 71 assertions. clj-kondo clean, cljfmt clean.

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

## Authorizer API

The `evaluate` function accepts an `:authorizer` keyword argument:

```clojure
(stroopwafel.core/evaluate token
  :authorizer {:facts  [[:time (System/currentTimeMillis)]
                         [:resource "/api/data"]]
               :checks [{:id    :check-read
                         :query [[:can "alice" :read "/api/data"]]}]
               :rules  '[{:id   :can-from-right
                          :head [:can ?u ?a ?r]
                          :body [[:right ?u ?a ?r]]}]})
```

Authorizer facts/rules/checks are evaluated with scope `#{0 :authorizer}` —
they see authority block facts but not delegated block facts.

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

### Phase 3: Biscuit Parity
- Token sealing
- Revocation IDs
- Third-party blocks
- Ephemeral keys per attenuation block
- Full Datalog: scopes, expressions, built-in functions

### Phase 4: Multi-platform
- .cljc throughout (JVM + Babashka + potentially CLJS)
- Cross-platform crypto (JCA on JVM, TBD on JS)

## License

EPL-2.0 (CEDN license). KEX attribution preserved per EPL-1.0.
