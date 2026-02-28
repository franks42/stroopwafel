# Biscuit Gap Analysis — Stroopwafel v0.3.0

Current status of Stroopwafel against the Biscuit specification (v3.3).
Updated Feb 2026 after Phase 3a completion.

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
| Ephemeral keys per block | Yes | ✓ Yes | Done (v0.3.0) |
| Datalog expressions | Yes | **No** | Open — **high priority** |
| Revocation IDs | Yes | ✓ Yes | Done (v0.3.0) |
| Authorizer policies | Yes | ✓ Yes | Done (v0.3.0) |
| Sealed tokens | Yes | **No** | Open — easy (depends on ephemeral keys) |
| Third-party blocks | Yes | **No** | Open — medium |
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

### Revocation IDs — ✓ Done (v0.3.0)

SHA-256 of each block's `:sig` bytes, returned as 64-char lowercase hex strings.
`revocation-ids` function in `core.clj`. Revocation checking is application-level
(set or bloom filter lookup). Revoking any block's ID invalidates the entire
token (append-only chain).

### Authorizer Policies — ✓ Done (v0.3.0)

Ordered allow/deny policies evaluated after all block checks pass. First matching
policy wins. No match = deny (closed-world default). Distinct from per-block
checks — policies determine the final authorization decision.

Policies only see authority + authorizer facts (scope `#{0 :authorizer}`),
not delegated block facts.

### Ephemeral Keys Per Block — ✓ Done (v0.3.0)

Each attenuation block gets a fresh Ed25519 keypair:
- `authority-block` generates first ephemeral keypair, signs with root key
- `delegated-block` signs with current ephemeral key, generates next keypair
- `verify-chain` validates ephemeral key threading (block i verified with
  block i-1's `:next-key`)
- Each block's `:prev-sig` binds it to the previous signature

Token format: `{:blocks [...] :proof <ephemeral-private-key>}`. Whoever holds
the token can attenuate — no separate key argument needed. The attenuation
guarantee is now enforced by both Datalog scoping AND cryptography.

---

## Open Gaps (Phase 3b, priority order)

### 1. Datalog Expressions — High Priority

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

### 2. Sealed Tokens — Easy (ephemeral keys now implemented)

**What Biscuit does**: A token can be "sealed" to prevent further attenuation.
The seal encrypts the last ephemeral private key, making it impossible to
append new blocks.

**Current state**: No sealing mechanism. Any holder with the key can attenuate.

**Implementation**: Add `:sealed?` flag or encrypt/discard the attenuation key
material. `attenuate` should reject sealed tokens.

**Note**: This depends on ephemeral keys (#1) — sealing is only meaningful when
each block has its own key.

**Files affected**: `core.clj` (minor), `block.clj` (minor)

### 3. Third-Party Blocks — Medium

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

## Crypto Primitives Required

Current `crypto.clj` provides: Ed25519 sign/verify, SHA-256, CEDN encoding,
public key encode/decode. **No encryption primitives exist today.** Analysis:

| Feature | New Crypto? | What's Needed |
|---------|-------------|---------------|
| Revocation IDs | No | `sha256` already exists — derive from `:sig` bytes |
| Authorizer policies | No | No crypto involved — pure Datalog evaluation |
| Ephemeral keys | No | `generate-keypair` already exists — change is structural (key threading) |
| Sealed tokens | **Maybe** | Option A: HMAC-SHA256 (simple, irreversible seal) — discard ephemeral key, store HMAC proof. Option B: AES-GCM (reversible seal) — encrypt ephemeral key so original sealer can unseal. Option A is sufficient for most use cases. |
| Third-party blocks | No | `sign`/`verify` already exist — needs per-block public key validation |
| Datalog expressions | No | No crypto involved — pure evaluation |

**Bottom line**: Sealed tokens are the only feature that may require a new crypto
primitive (HMAC-SHA256 or AES-GCM). Everything else is covered by existing
sign/verify/hash operations. The sealed tokens decision can be deferred until
ephemeral keys are implemented (sealing depends on ephemeral keys).

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
