# Biscuit Gap Analysis — Stroopwafel v0.2.0

Current status of Stroopwafel against the Biscuit specification (v3.3).
Updated Feb 2026 after Phase 2 completion.

See `biscuit-kex-analysis.md` for the original KEX research and Biscuit
background. This document tracks only the gap status.

---

## Summary Table

| Feature | Biscuit | Stroopwafel | Status |
|---------|---------|-------------|--------|
| Ed25519 signatures | Yes | ✓ Yes | Done |
| Append-only block chain | Yes | ✓ Yes | Done |
| Block isolation / scoping | Yes | ✓ Yes | Done (v0.2.0) |
| Deny rules (reject-if) | Yes | ✓ Yes | Done (v0.2.0) |
| Authorizer context | Yes | ✓ Yes | Done (v0.2.0) |
| Scoped rule evaluation | Yes | ✓ Yes | Done (v0.2.0) |
| Fixpoint rule evaluation | Yes | ✓ Yes | Done (v0.2.0) |
| Canonical serialization | Protobuf | ✓ CEDN | Done (v0.1.0) — different wire format |
| Proof visualization | No | ✓ Yes | Stroopwafel-only feature |
| Ephemeral keys per block | Yes | **No** | Open — **high priority** |
| Datalog expressions | Yes | **No** | Open — **high priority** |
| Revocation IDs | Yes | **No** | Open — easy |
| Sealed tokens | Yes | **No** | Open — easy |
| Third-party blocks | Yes | **No** | Open — medium |
| Authorizer policies | Yes | Partial | Authorizer checks exist, not full allow/deny policies |
| Cross-platform | Multi-lang | JVM only | Open — bb ready, CLJS needs work |

---

## Closed Gaps

### Block Isolation — ✓ Fixed (v0.2.0)

**Was the biggest gap.** All facts were pooled into a single namespace tagged
`{:origin :authority}`. Delegated blocks could inject facts that expand
authority, inverting Biscuit's core attenuation guarantee.

**Implementation**:
- Facts tagged with set-based origins: `#{0}` (authority), `#{n}` (block n),
  `#{:authorizer}` (authorizer context)
- Rules in block N only see facts from `#{0 N :authorizer}`
- Authorizer checks only see `#{0 :authorizer}`
- Derived facts carry union of input origins + rule block index
- Scope filtering via `(subset? fact-origin trusted-origins)`
- 9 dedicated scoping tests validate the guarantee

### Deny Rules — ✓ Fixed (v0.2.0)

Checks with `:kind :reject` fail when the query matches (inverse of normal
`check-if` semantics). Enables revoking capabilities, banning users/resources,
and context-based restrictions.

Note: Biscuit also has **authorizer policies** (`allow if` / `deny if`) which
are distinct from per-block checks. Stroopwafel's authorizer checks serve a
similar role but are structurally checks, not policies. The semantic difference
is minor — both prevent authorization when matched/unmatched.

### Scoped + Fixpoint Rule Evaluation — ✓ Fixed (v0.2.0)

Rules fire per-block with scope filtering, running to fixpoint (max 100
iterations, 1000 facts). Previous KEX code fired rules only once and with no
scope filtering.

### Canonical Serialization — ✓ Fixed (v0.1.0)

Replaced `pr-str` + `sorted-map` with CEDN `canonical-bytes` — deterministic,
spec-backed, cross-platform. Single function call in `encode-block`.

Note: Biscuit uses Protobuf for wire format. Stroopwafel uses CEDN. This means
tokens are **not interoperable** with other Biscuit implementations. This is a
deliberate choice — CEDN is EDN-native, human-readable, and cross-platform
within the Clojure ecosystem.

---

## Open Gaps (Phase 3, priority order)

### 1. Ephemeral Keys Per Block — High Priority

**What Biscuit does**: Generates a fresh Ed25519 key pair for each appended
block. Each block's signature covers its content + the next block's public key.
Only the holder of the current ephemeral private key can attenuate further.

**Current state**: Stroopwafel reuses the same key for all blocks. Any
attenuator who knows the signing key can forge blocks at any position in the
chain.

**Impact**: Without this, the crypto scheme is weaker than Biscuit's — the
attenuation guarantee is enforced by Datalog scoping but not by cryptography.

**Difficulty**: Medium. Requires reworking `block.clj`:
- `authority-block` generates first ephemeral keypair
- `delegated-block` signs with current ephemeral key, generates next keypair
- `verify-chain` validates ephemeral key threading
- `attenuate` API returns new ephemeral private key for further attenuation

**Files affected**: `block.clj`, `core.clj`, `crypto_test.clj`

### 2. Datalog Expressions — High Priority

**What Biscuit does**: Rule and check bodies can include expression nodes
alongside fact patterns:
```
check if time($time), $time < 2026-03-01T00:00:00Z;
check if amount($a), $a <= 100;
check if resource($r), $r.starts_with("/public/");
```

**Current state**: Only fact pattern matching. No arithmetic, comparisons,
string operations, or date handling in rule/check bodies.

**Impact**: Can't implement time-based token expiry (the #1 real-world use
case), amount limits, or string prefix matching.

**Difficulty**: Hard. Requires:
- New expression AST (comparison, arithmetic, string ops, date ops)
- Expression evaluator that runs in the context of bound variables
- Extending `eval-body` to handle expression nodes after pattern matching
- Built-in functions: `<`, `>`, `<=`, `>=`, `==`, `!=`, `+`, `-`, `*`,
  `.starts_with`, `.ends_with`, `.contains`, `.length`, `.intersection`,
  `.union`, `.difference`

**Files affected**: `datalog.clj` (major), `datalog_test.clj` (major)

### 3. Revocation IDs — Easy

**What Biscuit does**: Each block has a revocation ID derived from its
signature hash. Applications maintain revocation lists to invalidate tokens.

**Current state**: No revocation IDs. Tokens cannot be invalidated after
issuance.

**Implementation**: Derive IDs from existing `:sig` bytes (`SHA-256` of
signature). Add `revocation-ids` function to `core.clj` that extracts IDs from
a token. Revocation checking is application-level (set or bloom filter lookup).

**Files affected**: `core.clj` (minor), `core_test.clj` (minor)

### 4. Sealed Tokens — Easy

**What Biscuit does**: A token can be "sealed" to prevent further attenuation.
The seal encrypts the last ephemeral private key, making it impossible to
append new blocks.

**Current state**: No sealing mechanism. Any holder with the key can attenuate.

**Implementation**: Add `:sealed?` flag or encrypt/discard the attenuation key
material. `attenuate` should reject sealed tokens.

**Note**: This depends on ephemeral keys (#1) — sealing is only meaningful when
each block has its own key.

**Files affected**: `core.clj` (minor), `block.clj` (minor)

### 5. Third-Party Blocks — Medium

**What Biscuit does**: External parties can sign blocks included in the chain
without seeing the full token. Enables delegated attestation ("IdP X attests
user has role Y").

**Current state**: All blocks must be signed with the same key (or by someone
who has the attenuation key).

**Implementation**: Requires:
- Per-block public key validation (not just authority key)
- Third-party block request/response protocol
- Separate signature verification path for third-party blocks
- Scope rules: third-party block facts are scoped to that block

**Priority**: Low-medium. Advanced delegation pattern not needed for most
single-issuer use cases.

**Files affected**: `block.clj` (medium), `core.clj` (medium),
`crypto.clj` (minor)

---

## Not Planned / Deferred

### Protobuf Wire Format

Biscuit uses Protobuf for token serialization, enabling interoperability
across Rust, Java, Go, Python, etc. Stroopwafel uses CEDN instead.

**Status**: Deliberately different. CEDN is human-readable, EDN-native, and
cross-platform within the Clojure ecosystem. Matching Protobuf would enable
interop with other Biscuit implementations but would add a Protobuf dependency
and lose the EDN advantages.

**Revisit when**: There is concrete demand for cross-language token exchange.

### Full Biscuit Conformance Suite

The Biscuit project has a conformance test suite. Running against it requires
Protobuf wire format compatibility, which we don't have.

**Revisit when**: If Protobuf wire format is implemented.
