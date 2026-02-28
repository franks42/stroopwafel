# Biscuit & KEX Analysis — Stroopwafel Design Reference

Consolidated from research sessions (Feb 2026). This document captures the
analysis of Biscuit, KEX, and the gap between them that Stroopwafel aims to fill.

---

## 1. What is Biscuit?

Eclipse Biscuit is an authorization token for distributed systems (Eclipse
Foundation project, 2025). Core idea: cryptographically signed bearer token
carrying Datalog-based authorization logic. "JWT meets Macaroons meets Datalog."

Key features:
- **Decentralized verification** — Ed25519 public key, no callback to issuer
- **Offline attenuation** — append-only blocks that can only restrict, never
  expand rights
- **Capability-based authorization** — token carries what the bearer can do,
  not who they are
- **Revocation IDs** — derived from block signatures, enabling revocation lists

Spec version: v3.3. Production use at Clever Cloud (Apache Pulsar) and 3DS
Outscale IAM.

Implementations: Rust (reference, ~227 stars), Java (v3.3 in progress), Go,
Python, Haskell, WASM, .NET. **No official Clojure implementation exists.**

### Token Format

```
Token = AuthorityBlock + [AttenuationBlock...] + [ThirdPartyBlock...]
```

- **Authority block** (block 0): signed by the issuer's private key, carries
  initial facts, rules, and checks
- **Attenuation blocks** (1..n): each signed with an ephemeral key, can only
  add restrictions (checks, deny rules), never new authority facts
- **Third-party blocks**: signed by external keys, included in the chain for
  delegated attestation
- **Sealed tokens**: frozen — no further attenuation possible

### Crypto Scheme

- Ed25519 signature chain: each block's signature covers its content + the
  previous block's public key
- Ephemeral keys per attenuation block (new key pair generated for each
  appended block)
- Revocation IDs: hash of each block's signature

### Datalog Authorization

Facts, rules, checks, and policies — scoped per block:
- Facts in block 0 (authority) are trusted
- Facts in block N are local to that block
- Rules can derive new facts within their scope
- Checks must all pass for authorization to succeed
- Policies (allow/deny) evaluated by the authorizer

## 2. Adoption Context

**Challenges**: ecosystem inertia (JWT/OAuth deeply entrenched), token size
growth in deep attenuation chains, Datalog learning curve, pending cryptographic
audit, infrastructure expects JWT/OAuth.

**Strengths**: Eclipse Foundation backing, production deployments, more
principled than JWT flat claims model, natural fit for distributed systems and
multi-agent AI architectures where trust is graduated and contextual.

**AI agent thesis** (Seref Ayar blog series): AI agents in distributed systems
need principled authorization. Biscuit's capability model is a natural fit — as
LLM agents gain tool/API access, graduated and contextual trust becomes
essential.

Blog series by Seref R. Ayar:
- "De-mystifying Agentic AI" (Jan 28, 2026)
- "OCapN and Structural Authority in Agentic AI"
- "Interpreting OCapN Principles in Cloud-Native Agentic AI Architectures"
- "Reconstructing Biscuit in Clojure" (Feb 19, 2026) — introduces KEX

## 3. KEX — What It Is

KEX (github.com/serefayar/kex) is a pure Clojure proof-of-concept
reimplementation of Biscuit's core ideas by Seref R. Ayar. ~470 LOC (some
sources say ~700 with tests), zero external dependencies, EPL-1.0.

**NOT a wrapper around biscuit-java** — from-scratch implementation, no
interoperability with real Biscuit tokens.

### Architecture

| Module | Purpose |
|--------|---------|
| `kex.core` | Public API: `new-keypair`, `issue`, `attenuate`, `verify`, `evaluate` |
| `kex.crypto` | Ed25519 sign/verify, SHA-256, canonical serialization via `pr-str` |
| `kex.block` | Authority/delegated block creation, chain verification |
| `kex.datalog` | Minimal Datalog: unification, rule firing, check evaluation |
| `kex.graph` | Proof tree visualization |

### Strengths

- Excellent for **learning Biscuit concepts** — small enough to read in one
  sitting
- Proof trees make authorization logic transparent
- REPL-friendly
- Pure Clojure, no external deps

## 4. KEX Gaps — Stroopwafel Status

### 4.1 Block Isolation (SECURITY CRITICAL) — ✓ Fixed (v0.2.0)

**Was the biggest gap.** All facts were pooled into a single namespace tagged
`{:origin :authority}`. Delegated blocks could inject facts that **expand**
authority, inverting Biscuit's core attenuation guarantee.

**Fix implemented in v0.2.0**:
- Facts tagged with set-based origins: `#{0}` (authority), `#{n}` (block n),
  `#{:authorizer}` (authorizer context)
- Rules in block N only see facts from `#{0 N :authorizer}`
- Authorizer checks only see `#{0 :authorizer}`
- Derived facts carry union of input origins + rule block index
- Scope filtering via `(subset? fact-origin trusted-origins)`
- 9 dedicated scoping tests validate the guarantee

### 4.2 Deny Rules / Negative Constraints — ✓ Fixed (v0.2.0)

**Implemented.** Checks with `:kind :reject` fail when the query matches
(inverse of normal `check-if` semantics). Enables:
- Revoking specific capabilities
- Banning users/resources
- Context-based restrictions

Note: Biscuit also has **authorizer policies** (`allow if` / `deny if`) which
are distinct from per-block checks. Stroopwafel's authorizer checks serve a
similar role but are structurally checks, not policies. The semantic difference
is minor — both prevent authorization when matched/unmatched.

### 4.3 No Third-Party Blocks — Open

Biscuit allows external parties to sign blocks that are included in the chain.
This enables delegated attestation patterns (e.g., "identity provider X attests
that this user has role Y").

**Difficulty**: Medium. Requires per-block public key validation (not just the
authority key), and a request/response protocol for the third party to sign a
block without seeing the full token.

**Priority**: Low-medium. Advanced delegation pattern, not needed for most
single-issuer use cases.

### 4.4 No Sealed Tokens — Open

No way to freeze a token to prevent further attenuation.

**Difficulty**: Easy. Options include encrypting the last block's ephemeral
private key, adding a seal marker, or simply omitting the key material needed
for further attenuation.

**Priority**: Medium. Useful for "final form" tokens sent to end-users.

### 4.5 No Revocation Support — Open

No revocation IDs derived from block signatures, no way to maintain revocation
lists.

**Difficulty**: Easy. Derive IDs from existing `:sig` bytes (SHA-256 of
signature). Revocation checking is application-level (set/bloom filter lookup).

**Priority**: Medium. Important for production use but trivial to implement.

### 4.6 No Ephemeral Keys Per Block — Open

Biscuit generates a fresh key pair for each appended block. The signature chain
links blocks via: each block's signature covers content + next block's public
key. This means only the holder of the current ephemeral key can attenuate.

Currently stroopwafel reuses the same key for all blocks, which means any
attenuator who knows the key can forge blocks at any position in the chain.

**Difficulty**: Medium. Requires reworking `block.clj`'s signing/verification
to thread ephemeral public keys through the chain.

**Priority**: High for production security. Without ephemeral keys, the crypto
scheme is weaker than Biscuit's — an attenuator could forge earlier blocks.

### 4.7 Ad-Hoc Serialization — ✓ Fixed (v0.1.0)

**Fixed.** Replaced `pr-str` + `sorted-map` with CEDN `canonical-bytes` —
deterministic, spec-backed, cross-platform. Single function call in
`encode-block`.

### 4.8 Limited Datalog — Partially Fixed (v0.2.0)

**Fixed in v0.2.0**:
- ✓ Scoped rule evaluation (per-block with scope filtering)
- ✓ Recursive/fixpoint rule evaluation (max 100 iterations, 1000 facts)

**Still missing**:
- Expressions in rule/check bodies (arithmetic, string ops, date comparisons)
- Built-in functions (`$time < 2026-03-01`, `$amount <= 100`, string matching)

**Difficulty**: Hard. Requires extending the Datalog body pattern language to
support expression nodes alongside fact patterns. Time-based expiry is the #1
real-world use case that depends on this.

**Priority**: High for real-world use. Without expressions, you can't do
time-based token expiry, amount limits, or string prefix matching.

### 4.9 JVM-Only — Open

No .cljc, no ClojureScript/Babashka portability.

**Difficulty**: Medium. CEDN is already cross-platform (.cljc). Babashka has
full JDK crypto (confirmed working). CLJS would need Web Crypto API adapter.

**Priority**: Medium. Babashka support is nearly free (just .cljc rename +
test). CLJS requires more work.

## 5. CEDN Integration

CEDN (Canonical EDN, `com.github.franks42/cedn` v1.2.0) provides the
deterministic serialization layer that KEX lacks.

### Why CEDN

- **Deterministic**: same value → same bytes, always, on every platform
- **Spec-backed**: CEDN-P specification with compliance test vectors
- **Cross-platform**: JVM, Babashka, nbb, shadow-cljs, Scittle (browser)
- **Zero deps**: only Clojure itself
- **Superset of Biscuit types**: CEDN-P covers all Biscuit data types (i64,
  string, date, bytes, boolean, set) plus keywords, symbols, lists, vectors,
  maps, nil, doubles

### Signing Pipeline

```
EDN data → canonical-bytes (UTF-8) → Ed25519 sign/verify
```

No text intermediary ambiguity — `canonical-bytes` goes directly to
deterministic UTF-8 bytes.

### Design Decision: CEDN-P Only

CEDN-R (BigInt, BigDecimal, ratios) is deprioritized indefinitely. Rationale:
- Cross-platform portability is paramount
- No realistic authorization scenario requires >64-bit integers, exact decimals,
  or ratios
- Financial amounts use integer smallest-units (cents, satoshis) fitting in
  64-bit Long

## 6. Babashka Crypto Capabilities

Babashka v1.12.215 (Java 25, GraalVM Substrate VM) has **full JDK crypto out of
the box**. Tested and confirmed working:

- **Ed25519**: keygen, sign, verify (~1400 sign ops/sec, ~1370 verify ops/sec)
- Ed448, EdDSA, RSA, EC, DSA
- X25519 key agreement
- SHA-256/384/512, SHA3-256/512, SHA-1, MD5 (~540K SHA-256 ops/sec)
- AES-GCM, AES-CBC, ChaCha20-Poly1305
- HMAC-SHA256/512
- PKCS12/JKS/JCEKS keystores
- X.509 CertificateFactory
- Base64, SecureRandom
- KeyFactory with X509EncodedKeySpec and PKCS8EncodedKeySpec

**All KEX `crypto.clj` operations run identically in bb.** No external crypto
dependencies needed.

Six security providers: SUN, SunRsaSign, SunEC, SunJSSE, SunJCE, JdkLDAP.

Note: `.getServices` method on Provider is NOT exposed in bb class allowlist,
but all algorithms work via `getInstance()`.

## 7. Recommendations

### Phase Status

1. **Phase 1** ✓ (v0.1.0): KEX source in `stroopwafel.*` namespaces, CEDN
   `canonical-bytes` for signing, 27 tests passing
2. **Phase 2** ✓ (v0.2.0): Block isolation, scope filtering, deny rules,
   authorizer API, fixpoint rule evaluation, 38 tests passing
3. **Phase 3** (next): Ephemeral keys, Datalog expressions, revocation IDs,
   sealed tokens, third-party blocks
4. **Phase 4**: .cljc throughout (JVM + Babashka + potentially CLJS)

### Phase 3 Priority Order

1. **Ephemeral keys** — security hardening, without this the crypto scheme is
   weaker than Biscuit's (attenuators can forge earlier blocks)
2. **Datalog expressions** — time-based expiry is the #1 real-world use case
3. **Revocation IDs** — trivial to derive, important for production
4. **Sealed tokens** — easy, useful for final-form tokens
5. **Third-party blocks** — advanced, lower priority

### Do Not Use biscuit-java

KEX is a from-scratch implementation. Wrapping biscuit-java via Java interop
would be the most pragmatic path to spec compliance but would lose the pure
Clojure advantages (REPL-friendliness, transparency, portability). Stroopwafel
continues the pure Clojure approach.

### Biscuit Conformance

The Biscuit project has a conformance test suite. Once Stroopwafel reaches
Phase 3, running against these tests would validate correctness. However, full
Biscuit interoperability (reading/writing tokens compatible with other
implementations) requires matching their Protobuf wire format, which is a
separate decision.

## 8. Summary Table

| Feature | Biscuit | KEX | Stroopwafel v0.2.0 |
|---------|---------|-----|--------------------|
| Ed25519 signatures | Yes | Yes | ✓ Yes |
| Block chain | Yes | Yes | ✓ Yes |
| Datalog engine | Full | Minimal | Scoped + fixpoint (no expressions) |
| Block isolation | Yes | **No** | ✓ **Yes** (v0.2.0) |
| Deny rules | Yes | **No** | ✓ **Yes** (v0.2.0) |
| Authorizer context | Yes | **No** | ✓ **Yes** (v0.2.0) |
| Scoped rules | Yes | **No** | ✓ **Yes** (v0.2.0) |
| Fixpoint evaluation | Yes | **No** | ✓ **Yes** (v0.2.0) |
| Datalog expressions | Yes | **No** | **No** |
| Third-party blocks | Yes | **No** | **No** |
| Sealed tokens | Yes | **No** | **No** |
| Revocation IDs | Yes | **No** | **No** |
| Ephemeral keys | Yes | **No** | **No** |
| Canonical serialization | Protobuf | pr-str | ✓ **CEDN** (v0.1.0) |
| Cross-platform | Multi-lang | JVM only | JVM only (bb ready) |
| Dependencies | Varies | Zero | CEDN only |
| Proof visualization | No | Yes | ✓ Yes |
