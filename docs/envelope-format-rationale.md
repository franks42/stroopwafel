# Envelope Format Rationale: Why Not JWS?

> JWS uses base64 to work around JSON's lack of canonicality.
> CEDN eliminates the need for the workaround. The result is
> a simpler signing pipeline with fewer moving parts.

---

## The Canonicalization Problem

To sign a data structure, you need a deterministic byte sequence.
The same logical value must produce the same bytes every time,
on every platform. Without this, the signature computed by the
signer won't match the signature verified by the verifier.

JSON does not have a canonical form:

```json
{"a":1,"b":2}      ← valid JSON
{"b":2,"a":1}      ← same value, different bytes
{ "a" : 1, "b" : 2 }  ← same value, different bytes again
```

JWS (RFC 7515) solves this with base64url encoding: serialize
the JSON however you like, then base64url-encode the result.
The base64url string IS the canonical form — it's just bytes,
and the signing input is defined as the encoded representation,
not the logical value:

```
JWS signing input:
  base64url(header) + "." + base64url(payload)
  ─────────────────────────────────────────────
  A string. Canonical by construction.
  The JSON inside doesn't need to be canonical
  because we're signing the encoding, not the value.
```

This works, but it means every JWS implementation must:
1. Serialize to JSON (non-canonical)
2. Base64url-encode the JSON bytes
3. Concatenate header and payload with a dot separator
4. Sign the concatenated string
5. Base64url-encode the signature
6. Concatenate all three with dots

Six steps. Three base64 operations. Two concatenations.

---

## The CEDN Solution

Canonical EDN (CEDN) is deterministic by design: same value,
same bytes, always. Map keys are sorted. Sets are normalized.
Nested structures are recursively canonicalized. The `#bytes`
tagged literal handles byte arrays natively.

```clojure
(cedn/canonical-bytes {:b 2 :a 1})
;; always produces the same bytes as
(cedn/canonical-bytes {:a 1 :b 2})
```

This means we can sign the value directly:

```
Stroopwafel signing input:
  sha256( cedn/canonical-bytes(envelope) )
  ────────────────────────────────────────
  The canonical byte representation of the value itself.
  No encoding layer. No concatenation. No workaround.
```

The signing pipeline is:
1. Construct the envelope as an EDN map
2. `cedn/canonical-bytes` → deterministic byte sequence
3. SHA-256 → hash
4. Ed25519 sign the hash

Four steps. Zero base64. Zero concatenation.

---

## Side-by-Side Comparison

### JWS (RFC 7515)

```
Header:    {"alg":"EdDSA","kid":"key-123"}
Payload:   {"sub":"alice","exp":1711234687}

Signing:   sign( b64url(header) + "." + b64url(payload) )

Wire:      eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhbGljZSJ9.sig-bytes-b64
           ───────────────────── ───────────────────── ─────────────
           header (b64)          payload (b64)         signature (b64)
```

### Stroopwafel Envelope

```clojure
Envelope:  {:message    {:method "post" :path "/market/quote"
                         :body {:symbol "AAPL"}}
            :signer-key #bytes "a1b2c3..."
            :request-id "019d0114-8fb5-7806-b96a-980f2ff0f51f"
            :expires    1711234687000}

Signing:   sign( sha256( cedn/canonical-bytes(envelope) ) )

Wire:      {:envelope <above> :signature #bytes "d4e5f6..."}
```

---

## Unified Signing: Blocks Use the Same Format

As of v0.10.2, token blocks also use the signed-envelope format. Every
signed structure in stroopwafel is a self-describing envelope:

```clojure
{:type      :stroopwafel/signed-envelope
 :envelope  {:message    {:facts [...] :rules [...] :checks [...]
                          :prev-sig ... :next-key ...}
             :signer-key pk-bytes
             :request-id "uuid"}
 :signature sig-bytes}
```

Tokens carry `:type :stroopwafel/token`. The `:type` field enables
multimethod dispatch — code can handle any signed structure uniformly
without inspecting its internals.

This unification eliminates the old pattern of `dissoc :hash :sig`
before verification. The payload (`:envelope`) and the signature
(`:signature`) are cleanly separated at the top level. Nested signing
works naturally — an envelope's message can itself be a signed
envelope, turtles all the way down, for multi-signature scenarios.

`:expires` is optional in envelopes (nil ttl = no expiry). Validity
constraints are a policy concern expressed as Datalog facts, not a
transport-level field.

---

## What the Payload Can Be

The payload is not required to be CEDN — it is any EDN value
that is canonicalizable, i.e., can be converted to canonical
EDN via `cedn/canonical-bytes`. This includes:

- Maps (key order doesn't matter — CEDN sorts them)
- Vectors, lists, sets
- Strings, keywords, numbers, booleans, nil
- Byte arrays (`#bytes`)
- Nested combinations of all of the above

The author writes regular EDN — whatever is natural for the
application. Canonicalization happens at signing time,
transparently. The author never thinks about canonical form.

---

## Feature Comparison

| Concern | JWS (RFC 7515) | Stroopwafel envelope |
|---|---|---|
| **Canonicalization** | base64url encoding (workaround) | CEDN (by design) |
| **Signing input** | `b64(header).b64(payload)` | `sha256(cedn(envelope))` |
| **Algorithm** | Negotiated via `alg` header | Fixed Ed25519 |
| **Signer identity** | `kid` header (key ID reference) | `:signer-key` (full pk bytes) |
| **Timestamp** | `iat` claim (optional) | UUIDv7 `:request-id` (mandatory, also nonce) |
| **Expiry** | `exp` claim (optional) | `:expires` (optional; validity via Datalog facts) |
| **Audience** | `aud` claim (optional) | `:audience` in message (optional) |
| **Replay protection** | `jti` claim (optional, no spec for checking) | UUIDv7 nonce + replay guard (built in) |
| **Requester binding** | None (DPoP/RFC 9449 bolted on later) | `:signer-key` + signed envelope (built in) |
| **Byte arrays** | base64url-encoded strings | `#bytes` tagged literal (native) |
| **Multi-signature** | JWS JSON serialization | Quorum (designed, not yet implemented) |
| **Serialization** | JSON + base64url | CEDN (one format throughout) |

---

## What JWS Gets Right

**Ecosystem.** JWS/JWT is everywhere. Libraries in every
language. Every API gateway, every OAuth provider, every
identity platform speaks JWT. If you need to interoperate with
the existing web identity ecosystem, JWS is the pragmatic choice.

**Algorithm agility.** The `alg` header allows different
algorithms (RS256, ES256, EdDSA, etc.). For a general-purpose
standard, this flexibility matters. For a single-purpose system
where everything is Ed25519, it's unnecessary complexity and an
attack surface (algorithm confusion attacks).

**Separation of header and payload.** The header contains
metadata about how the signature was produced. The payload
contains the claims. This separation is clean conceptually,
though it exists partly because both need to be base64-encoded
separately for the signing input.

---

## Why We Don't Use JWS

**We are EDN end-to-end.** Introducing JSON in the signing path
would mean: EDN → JSON → base64 → sign → base64 → JSON → EDN.
Every format conversion is a potential bug. CEDN keeps it as:
EDN → canonical bytes → sign. One format, one conversion.

**CEDN eliminates the problem JWS's base64 solves.** Base64
in JWS isn't a feature — it's a workaround for JSON's lack of
canonicality. With CEDN, the workaround is unnecessary.

**We want mandatory replay protection.** JWS defines `jti` but
doesn't require it or specify how to verify it. Our UUIDv7
request-id is mandatory, embeds a timestamp (freshness), and
serves as a nonce (uniqueness) — one field, two functions.

**We want built-in requester binding.** JWS is bearer-by-default.
DPoP (RFC 9449) was invented years later to add proof-of-possession.
Our envelope has signer-key and signature binding from the start.

**We don't need algorithm negotiation.** Everything is Ed25519.
Algorithm agility is an attack surface (algorithm confusion)
that we avoid by not having it.

---

## When to Use JWS Instead

If the system needs to:
- Interoperate with OAuth/OIDC providers
- Hand tokens to external parties who expect JWT
- Use existing JWT libraries and API gateways
- Support multiple signature algorithms

For internal systems (proxy ↔ agent, service ↔ service, browser
↔ server) where both sides speak EDN and trust the same
stroopwafel token format, the custom envelope is simpler and
more aligned with the data model.

If interoperability becomes necessary, the path is to add a JWS
serialization option — same logical envelope structure, different
wire encoding. The authorization model (Datalog evaluation,
trust roots, policy facts) doesn't change regardless of wire
format.

---

*Document status: design rationale.*
*Last updated: March 2026.*
*Related: `docs/datalog-as-authorization-join.md`,
`docs/identity-bootstrap-and-testing.md`,
[RFC 7515 — JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515),
[RFC 8037 — EdDSA for JOSE](https://datatracker.ietf.org/doc/html/rfc8037),
[RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)*
