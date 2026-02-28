# Stroopwafel — Canonical Authorization Tokens for Clojure

## What This Is

Stroopwafel is a capability-based authorization token library for Clojure,
inspired by [Biscuit](https://github.com/eclipse-biscuit/biscuit) and derived
from [KEX](https://github.com/serefayar/kex).

**Name origin**: cookie → biscuit → kex (Swedish) → stroopwafel (Dutch).
Like a stroopwafel: two layers with something sealed between them — signed
blocks wrapping authorized data.

## Goals

1. **Adopt canonical-edn (CEDN)** as the deterministic serialization layer,
   replacing KEX's ad-hoc canonicalization with `cedn/canonical-bytes` for
   all signing and verification.

2. **Achieve Biscuit feature parity** — the parts that matter for Clojure:
   - Append-only signed block chains (Ed25519)
   - Datalog authorization engine with proper scoping
   - Block isolation / attenuation (new blocks can only restrict, never expand)
   - Negative constraints (deny rules)
   - Third-party blocks
   - Revocation support
   - Token sealing

3. **Multi-platform** — JVM, Babashka, and potentially ClojureScript/nbb,
   following the same .cljc patterns as CEDN.

4. **Zero unnecessary deps** — Clojure + CEDN + JCA crypto only.

## Lineage

### From KEX (starting point)

KEX is a ~700-line proof-of-concept by Seref Ayar (EPL-1.0).
We copy and modify rather than fork because the changes are too fundamental
for upstream compatibility.

KEX provides the skeleton:
- `kex.core` — public API: `new-keypair`, `issue`, `attenuate`, `verify`, `evaluate`
- `kex.datalog` — minimal Datalog: unification, rule firing, check evaluation
- `kex.block` — authority/delegated block creation, chain verification
- `kex.crypto` — Ed25519 sign/verify, SHA-256, canonical serialization
- `kex.graph` — proof tree → graph visualization

KEX limitations to address:
- No block isolation (delegated blocks can expand authority)
- No negative constraints or deny rules
- No revocation
- No third-party blocks
- Ad-hoc canonicalization (not CEDN)
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

`com.github.franks42/cedn {:mvn/version "1.1.0"}` — deterministic EDN
serialization.  Same value → same bytes on all platforms.
Replaces KEX's `kex.crypto/canonical` with `cedn/canonical-bytes`.

## Architecture (planned)

```
stroopwafel/
├── deps.edn
├── bb.edn
├── build.clj
├── context.md                  ← this file
├── src/
│   └── stroopwafel/
│       ├── core.cljc           ← public API
│       ├── token.cljc          ← token structure, block chain
│       ├── crypto.cljc         ← Ed25519, SHA-256, CEDN signing
│       ├── datalog.cljc        ← Datalog engine (facts, rules, checks, policies)
│       └── graph.cljc          ← proof visualization
└── test/
    └── stroopwafel/
        └── *_test.cljc
```

## Dependencies (planned)

```clojure
{:paths ["src"]
 :deps {org.clojure/clojure {:mvn/version "1.12.0"}
        com.github.franks42/cedn {:mvn/version "1.1.0"}}}
```

Production deps: Clojure + CEDN only.
CEDN itself has zero transitive deps.

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

### Phase 1: Foundation
- Copy KEX source into `stroopwafel.*` namespaces
- Replace `kex.crypto/canonical` with CEDN `canonical-bytes`
- Get existing KEX tests passing under new namespace
- Add CEDN as a Maven dependency

### Phase 2: Block Isolation & Attenuation
- Enforce that delegated blocks can only restrict, never expand authority
- Proper scoping: authority facts vs block-local facts
- Negative constraints (deny rules)

### Phase 3: Biscuit Parity
- Token sealing
- Revocation IDs
- Third-party blocks
- Full Datalog: scopes, expressions, built-in functions

### Phase 4: Multi-platform
- .cljc throughout (JVM + Babashka + potentially CLJS)
- Cross-platform crypto (JCA on JVM, TBD on JS)

## License

EPL-2.0 (CEDN license). KEX attribution preserved per EPL-1.0.
