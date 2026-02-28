# Stroopwafel — Canonical Authorization Tokens for Clojure

## What This Is

Stroopwafel is a capability-based authorization token library for Clojure,
inspired by [Biscuit](https://github.com/eclipse-biscuit/biscuit) and derived
from [KEX](https://github.com/serefayar/kex).

**Name origin**: cookie → biscuit → kex (Swedish) → stroopwafel (Dutch).
Like a stroopwafel: two layers with something sealed between them — signed
blocks wrapping authorized data.

**Current version**: v0.1.0 (Phase 1 complete)

## Goals

1. **Adopt canonical-edn (CEDN)** as the deterministic serialization layer,
   replacing KEX's ad-hoc canonicalization with `cedn/canonical-bytes` for
   all signing and verification. ✓ Done

2. **Achieve Biscuit feature parity** — the parts that matter for Clojure:
   - Append-only signed block chains (Ed25519) ✓ (from KEX)
   - Datalog authorization engine with proper scoping
   - Block isolation / attenuation (new blocks can only restrict, never expand)
   - Negative constraints (deny rules)
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

KEX provides the skeleton:
- `kex.core` — public API: `new-keypair`, `issue`, `attenuate`, `verify`, `evaluate`
- `kex.datalog` — minimal Datalog: unification, rule firing, check evaluation
- `kex.block` — authority/delegated block creation, chain verification
- `kex.crypto` — Ed25519 sign/verify, SHA-256, CEDN canonical serialization
- `kex.graph` — proof tree → graph visualization

KEX limitations to address:
- No block isolation (delegated blocks can expand authority) ← **SECURITY CRITICAL**
- No negative constraints or deny rules
- No revocation
- No third-party blocks
- ~~Ad-hoc canonicalization (not CEDN)~~ ✓ Fixed in v0.1.0
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

## Current Architecture (v0.1.0)

```
stroopwafel/
├── deps.edn
├── context.md                  ← this file
├── docs/
│   ├── biscuit-kex-analysis.md ← detailed analysis of Biscuit, KEX, and gaps
│   └── bytes-support.md        ← CEDN #bytes feature request (implemented)
├── src/
│   └── kex/                    ← KEX namespaces (to be renamed to stroopwafel/)
│       ├── core.clj            ← public API
│       ├── block.clj           ← block chain structure
│       ├── crypto.clj          ← Ed25519, SHA-256, CEDN signing
│       ├── datalog.clj         ← Datalog engine
│       └── graph.clj           ← proof visualization
└── test/
    └── kex/
        ├── crypto_test.clj     ← 12 tests
        ├── datalog_test.clj    ← 10 tests
        └── graph_test.clj      ← 5 tests
```

27 tests, 55 assertions. clj-kondo clean, cljfmt clean.

## Dependencies

```clojure
{:paths ["src" "resources"]
 :deps {org.clojure/clojure {:mvn/version "1.12.4"}
        com.github.franks42/cedn {:mvn/version "1.2.0"}}}
```

Production deps: Clojure + CEDN only.
CEDN itself has zero transitive deps.

## Key Design Decisions Made

1. **CEDN over pr-str**: `encode-block` is a single call to
   `cedn/canonical-bytes` — no manual canonicalization, no prep step.
   Deterministic, spec-backed, cross-platform.

2. **#bytes tagged literal**: CEDN 1.2.0 natively serializes byte arrays as
   `#bytes "deadbeef"` (lowercase hex). Eliminates the need for manual
   byte-to-hex conversion before serialization.

3. **KEX namespaces preserved for now**: Source lives in `kex.*` namespaces
   to maintain working tests during foundation work. Rename to `stroopwafel.*`
   will happen when we start Phase 2 changes.

4. **KEX's `canonical` function retained**: Still in `kex.crypto` and tested,
   but no longer used by `encode-block`. Can be removed when namespaces are
   renamed.

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

### Phase 2: Block Isolation & Attenuation
- Rename `kex.*` → `stroopwafel.*` namespaces
- Enforce that delegated blocks can only restrict, never expand authority
- Proper scoping: authority facts vs block-local facts
- Negative constraints (deny rules)

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
