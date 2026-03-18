# Biscuit Gap Analysis — Stroopwafel v0.9.0

Current status of Stroopwafel against the Biscuit specification (v3.3).
Updated Mar 2026 — beyond Biscuit parity with SPKI/SDSI features.

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
| Datalog expressions | Yes | ✓ Yes | Done (v0.5.0) — Clojure-native :when/:let |
| Revocation IDs | Yes | ✓ Yes | Done (v0.3.0) |
| Authorizer policies | Yes | ✓ Yes | Done (v0.3.0) |
| Sealed tokens | Yes | ✓ Yes | Done (v0.4.0) |
| Third-party blocks | Yes | ✓ Yes | Done (v0.6.0) |
| Cross-platform | Multi-lang | JVM + Babashka | Done (v0.7.0) — CLJS remains open |
| **Beyond Biscuit** | | | |
| Requester-bound tokens | No (bearer only) | ✓ Yes | Done (v0.8.0) — SPKI key binding |
| SDSI name binding | No | ✓ Yes | Done (v0.8.0) — Datalog patterns |
| Delegation chains | No | ✓ Yes | Done (v0.9.0) — signer attribution |
| Multi-token composition | No | ✓ Yes | Done (v0.9.0) — PDP/PEP separation |

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

### Sealed Tokens — ✓ Done (v0.4.0)

`seal` signs the last block's hash with the ephemeral private key, then
discards the key. The proof becomes `{:type :sealed :sig <bytes>}` — a
verifiable signature, but no one can append new blocks. `attenuate` throws
on sealed tokens. `verify` validates the seal against the last block's
`:next-key`.

No encryption needed — sealing is pure signing + key destruction.

**Reversible sealing** (encrypting the private key so the sealer can later
unseal) is deliberately not implemented. There is no realistic use case: if
you want an attenuatable token, don't seal it. If you want a frozen token,
seal it. Just keep the unsealed copy if you need to attenuate later.

### Datalog Expressions — ✓ Done (v0.5.0)

**What Biscuit does**: Custom expression syntax (`$time < 2026-03-01T00:00:00Z`).

**Stroopwafel approach**: Clojure-native forms with whitelisted built-in
functions (~35). No custom parser needed.

- `:when` guard clauses on rules, checks, and policies — vector of Clojure
  forms that must all return truthy
- `:let` bindings for computed intermediate values
- Mini-interpreter: `eval-expr` walks forms, substitutes variables, resolves
  functions from a closed `built-in-fns` registry
- Security: no `eval`, no `resolve`, no namespace lookup, no I/O
- Evaluation timing: `eval-body` -> `eval-let` -> `eval-when` -> `instantiate`
- Backward compatible — existing rules/checks/policies unchanged

Enables time-based token expiry, amount limits, string prefix matching,
arithmetic guards, and compound conditions.

See `docs/datalog-expressions-clj-design.md` for full design document.

### Third-Party Blocks — ✓ Done (v0.6.0)

**What Biscuit does**: External parties can sign blocks included in the chain
without seeing the full token. Enables delegated attestation ("IdP X attests
user has role Y").

**Implementation**:
- `third-party-request` extracts `{:previous-sig ...}` from token
- `create-third-party-block` signs `SHA-256(encode-block({:facts :rules :checks :previous-sig}))` with third party's key, binding content to a specific token
- `append-third-party` appends the signed block via the ephemeral key chain
- Dual signature: external-sig (third party) + chain sig (token holder)
- `verify-chain` validates both chain signatures and external signatures
- Authorizer trusts specific keys via `:trusted-external-keys` on `evaluate`
- Scope: trusted third-party block facts visible to authorizer rules, checks,
  and policies. First-party blocks cannot see third-party facts (per-block scope
  unchanged). Without `:trusted-external-keys`, third-party facts are invisible.
- Replay prevention: external signature is bound to the specific token's
  `previous-sig` — a block signed for token A fails verification on token B.

---

## Open Gaps

No feature gaps remain against the Biscuit specification (excluding wire format
interoperability and cross-platform support).

---

## Crypto Primitives Required

Current `crypto.clj` provides: Ed25519 sign/verify, SHA-256, CEDN encoding,
public key encode/decode. **No encryption primitives exist today.** Analysis:

| Feature | New Crypto? | What's Needed |
|---------|-------------|---------------|
| Revocation IDs | No | `sha256` already exists — derive from `:sig` bytes |
| Authorizer policies | No | No crypto involved — pure Datalog evaluation |
| Ephemeral keys | No | `generate-keypair` already exists — change is structural (key threading) |
| Sealed tokens | No | Implemented as sign + discard key. No encryption needed. Reversible sealing deliberately not supported — no realistic use case. |
| Datalog expressions | No | ✓ Done — pure evaluation, no crypto involved |
| Third-party blocks | No | ✓ Done — `sign`/`verify`/`encode-block` reused for external signatures |

**Bottom line**: No feature required new crypto primitives. All gaps were
closed with existing `sign`/`verify`/`sha256`/`encode-block` functions.

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
