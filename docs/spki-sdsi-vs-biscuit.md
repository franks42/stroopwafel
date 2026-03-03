# SPKI/SDSI vs Biscuit: Capability-Based Authorization Frameworks

## Context

This document compares two generations of capability-based authorization systems:
**SPKI/SDSI** (1996–1999), the IETF's attempt at a key-centric alternative to X.509,
and **Biscuit** (2019–present), a modern authorization token combining public-key
cryptography with Datalog-based policy evaluation. Both reject identity-centric
certificate models in favor of directly binding authorization to cryptographic keys,
but they diverge sharply in how they handle naming, group membership, delegation
evidence, and verification architecture.

The comparison is relevant to **Stroopwafel**, a capability-based authorization
token library for Clojure derived from KEX (Seref Ayar's proof-of-concept
Biscuit implementation) and using Canonical EDN (CEDN) for deterministic
serialization. Stroopwafel v0.6.0 has achieved full Biscuit feature parity
(block isolation, attenuation, deny rules, authorizer policies, expressions,
sealed tokens, third-party blocks, revocation IDs) and must now decide which
architectural extensions — particularly around authorizer state management and
distributed trust — to adopt next.

---

## 1. Origins and Motivations

### SPKI/SDSI

SPKI (Simple Public Key Infrastructure) and SDSI (Simple Distributed Security
Infrastructure) began as independent projects in the mid-1990s, both reacting
against the complexity and identity-centrism of X.509. SPKI, driven by Carl
Ellison and others, focused on authorization certificates that bind permissions
directly to keys. SDSI, designed by Ron Rivest and Butler Lampson at MIT, focused
on local naming — giving key holders the ability to define nicknames for other keys
within their own namespace. The two merged in 1996–1997, producing a unified
framework documented in RFC 2692 (Requirements) and RFC 2693 (Certificate Theory).

The core insight was that **a person's name is rarely of security interest** — what
matters is whether a given keyholder has been granted a specific authorization.
SPKI/SDSI replaced the X.509 question "who is this person?" with "is this key
authorized to do this thing?"

### Biscuit

Biscuit emerged from Geoffroy Couprie's work on distributed systems security at
Clever Cloud, motivated by the limitations of both JWTs and Macaroons. JWTs offer
public-key verification but no attenuation — you can't derive a less-powerful token
from an existing one. Macaroons offer attenuation through HMAC-chained caveats but
require distributing a shared secret to every verifier, creating a dangerous
single-point-of-compromise. Biscuit combines **public-key verification** (like JWT)
with **offline attenuation** (like Macaroons) through an aggregated signature scheme,
and adds a **Datalog-based policy language** for expressing complex authorization
logic.

---

## 2. Feature Comparison

### 2.1 Identity Model

| Aspect | SPKI/SDSI | Biscuit |
|--------|-----------|---------|
| **Principal** | Public key (or hash of key) | Public key (root key of token) |
| **Naming** | SDSI local names — each key defines names in its own namespace | None built-in — identity is opaque to the token format |
| **Identity binding** | Optional, via name certificates | Not addressed — authentication is external (e.g. OAuth) |
| **Philosophy** | "Keys are principals, names are convenience" | "Authorization, not authentication" |

Both systems treat **the public key itself as the primary identifier**. The
critical difference is that SDSI built a full local naming layer on top of keys,
while Biscuit deliberately omits naming. In Biscuit, if a token carries
`user("alice")`, that string is an application-level fact with no cryptographic
binding to any identity system — the token's authenticity comes solely from the
root key signature, not from any claim about who "alice" is.

### 2.2 Authorization Model

| Aspect | SPKI/SDSI | Biscuit |
|--------|-----------|---------|
| **Authorization primitive** | 5-tuple: ⟨Issuer, Subject, Delegation, Authorization, Validity⟩ | Facts, rules, checks, and policies in Datalog |
| **Permission representation** | S-expression tags with set intersection | Datalog facts (e.g. `right("file1", "read")`) |
| **ACL anchor** | Verifier's local ACL with `Self` as issuer | Authorizer's allow/deny policies |
| **Expressiveness** | Tag intersection (set-theoretic, limited) | Full Datalog with expressions/guards |
| **Combining permissions** | 5-tuple reduction: intersect adjacent authorizations and validity | Datalog rule evaluation: derive new facts from existing ones |

SPKI's 5-tuple reduction is essentially a chain-walking algorithm: given a chain
of certificates `⟨K1, K2, true, A1, V1⟩ + ⟨K2, K3, D2, A2, V2⟩`, reduce to
`⟨K1, K3, D2, A1∩A2, V1∩V2⟩`. Authorization can only shrink as the chain extends —
this is SPKI's version of attenuation. But the tag intersection mechanism is
purely syntactic (set intersection on S-expression tag structures), which limits
its expressiveness. Howell showed that tag intersection can produce sets not
representable by any finite set of authorization tags, making semantic completeness
impossible for any rewriting algorithm using SPKI tags alone.

Biscuit replaces this with Datalog, which can express role hierarchies, group
membership, temporal constraints, resource patterns, and arbitrary derived
permissions through rules. The tradeoff is that Datalog evaluation is more
computationally expensive than SPKI's linear chain reduction, but the expressiveness
gain is substantial.

### 2.3 Delegation and Attenuation

| Aspect | SPKI/SDSI | Biscuit |
|--------|-----------|---------|
| **Delegation mechanism** | Authorization certificate with `(propagate)` bit | Offline block appending with aggregated signatures |
| **Attenuation** | Tag intersection during 5-tuple reduction | Appended blocks can only add checks, never add authority |
| **Delegation depth** | Unlimited chain of certificates | Unlimited block appending (until sealed) |
| **Revoking delegation** | CRL, online revalidation, validity expiry | Revocation IDs checked against external revocation list |
| **Offline operation** | Fully offline — prover carries all certificates | Fully offline — attenuation needs no contact with authority |

Both systems support offline attenuation: a principal who holds a credential can
derive a weaker credential without contacting the original issuer. In SPKI, this
is done by issuing a new certificate with a narrower authorization tag. In Biscuit,
this is done by appending a new block with additional checks. The cryptographic
mechanisms differ — SPKI uses independent certificate signatures while Biscuit uses
an aggregated signature chain — but the authorization-theoretic result is the same:
**permissions can only shrink, never grow, as delegation extends.**

### 2.4 Verification Model

| Aspect | SPKI/SDSI | Biscuit |
|--------|-----------|---------|
| **Verifier** | Resource owner who holds an ACL anchored to `Self` | Any service holding the root public key |
| **Proof direction** | Prover assembles certificate chain, presents to verifier | Token holder presents token; authorizer evaluates |
| **Ambient facts** | Not formalized — verifier has only its ACL + presented certs | Explicit: authorizer injects `resource()`, `operation()`, `time()`, etc. |
| **Trust model** | Verifier trusts only its own ACL entries and valid cert chains from them | Authorizer trusts only authority block and its own facts (by default) |

SPKI describes an "authorization loop": authorization flows from the verifier's ACL,
through a certificate chain, and back to the verifier when the prover presents the
chain. The verifier performs 5-tuple reduction to determine if the prover's key is
authorized. This is a fully decentralized model — **there is no central authority,
only local ACLs and certificate chains connecting them.**

Biscuit's authorizer is structurally simpler: it loads token facts, injects ambient
facts about the current request, evaluates Datalog rules, and applies allow/deny
policies. But the authorizer is typically a single service-side component that holds
the root public key and makes all authorization decisions.

### 2.5 Data Format and Encoding

| Aspect | SPKI/SDSI | Biscuit |
|--------|-----------|---------|
| **Wire format** | Canonical S-expressions (LR(0) grammar, RFC 9804) | Protobuf + Ed25519 signatures |
| **Human-readable form** | Advanced transport S-expressions | Datalog text syntax |
| **Signature algorithm** | Flexible (RSA, DSA, ECDSA — specified per certificate) | Ed25519 (single algorithm, aggregated signatures) |
| **Canonicalization** | Canonical S-expression encoding defined in spec | Protobuf provides deterministic encoding |

---

## 3. Group Management: The Central Architectural Divergence

This is where the two frameworks differ most profoundly, and where the question
of distributed vs. centralized authority becomes concrete.

### 3.1 SDSI: Groups as Distributed Certificates

In SDSI, **group membership is a certificate** — a cryptographically signed assertion
made by some key holder that defines a name in their local namespace. To create a
group called "engineering," a principal `K_org` issues multiple name certificates:

```
;; K_org defines "engineering" as pointing to multiple keys
(cert (issuer (name K_org "engineering")) (subject K_alice))
(cert (issuer (name K_org "engineering")) (subject K_bob))
(cert (issuer (name K_org "engineering")) (subject K_charlie))
```

These are **4-tuples** (name certificates) — they carry no explicit authorization,
just a name binding. Authorization comes separately via 5-tuples:

```
;; K_resource grants read access to everyone K_org calls "engineering"
(cert (issuer K_resource)
      (subject (name K_org "engineering"))
      (propagate)
      (tag (read))
      (valid (not-after "2026-12-31")))
```

The critical architectural properties are:

**Distributed evidence.** The name certificates are signed objects that travel with
the request. When Alice wants to prove she's in the engineering group, she presents
the chain: (1) K_org's name cert saying `K_alice ∈ engineering`, and (2) K_resource's
auth cert granting `engineering → read`. The verifier (resource owner) reduces
these to `⟨Self, K_alice, ..., read, ...⟩` through 4-tuple name reduction followed
by 5-tuple authorization reduction.

**Issuer sovereignty.** Each principal defines names only within their own namespace.
`K_org`'s "engineering" is a completely different name from `K_other`'s "engineering."
Names are always relative to the defining key — there are no global names. This means
group definitions are **cryptographically attributable**: you can always verify *who*
said someone is in a group.

**No central lookup required.** The verifier doesn't need to call out to any
directory service to resolve group membership. Everything needed for the
authorization decision is presented as certificates in the proof chain. This is
fully offline, fully decentralized.

**Delegation of group authority.** Since name certificates support extended names
(`K_org`'s `"engineering"` could resolve to `K_team_lead`'s `"my-team"`), group
management itself can be delegated. An organization key can say "my engineering
group is whatever Team Lead X calls their team" — and that resolution happens
entirely through certificate chain reduction.

### 3.2 Biscuit: Groups as Authorizer-Side State

In standard Biscuit usage, **group membership lives in the authorizer's database**
and is injected as Datalog facts at verification time:

```datalog
// Token carries only the user identity
user("user_1234");

// Authorizer loads group membership from its database
group("user_1234", "engineering");
group("user_1234", "deploy-team");

// Authorizer defines group-level permissions
group_right("engineering", "repo-api", "read");
group_right("deploy-team", "repo-api", "write");

// Datalog rule derives effective permissions
right($user, $resource, $op) <-
  group($user, $g),
  group_right($g, $resource, $op);

// Policy
allow if user($user), resource($res), operation($op),
         right($user, $res, $op);
```

The token knows nothing about groups. All group machinery is server-side state.

**Centralized resolution.** The authorizer must have access to a database that
maps users to groups. This is a runtime dependency — if the database is down or
stale, authorization decisions may be wrong.

**No cryptographic attribution.** When the authorizer injects `group("user_1234",
"engineering")`, that fact is not signed by anyone. It's trusted because the
authorizer trusts its own facts. There's no way to verify *who* decided that
user_1234 belongs to engineering — that decision is embedded in the authorizer's
database, not in a signed certificate.

**Simpler operations.** No group certificates to issue, distribute, revoke, or
chain-reduce. Adding someone to a group is a database write, not a certificate
issuance. Revoking membership is a database delete, not a CRL update.

**Richer group logic.** Because groups are Datalog facts, the authorizer can express
nested groups, role hierarchies, temporal group membership, and any other structure
that Datalog can represent — all without changing the token format.

### 3.3 Comparison Summary

| Property | SDSI Groups | Biscuit Groups |
|----------|-------------|----------------|
| **Where membership lives** | Signed certificates carried by prover | Authorizer's database |
| **Cryptographic attribution** | Yes — issuer key signed the name cert | No — authorizer trusts its own injected facts |
| **Offline resolution** | Yes — all evidence travels with request | No — requires database lookup |
| **Revocation** | CRL or validity expiry on name certificate | Database delete (immediate) |
| **Delegation of group management** | Yes — via extended names and cert chains | No — whoever controls the database controls groups |
| **Operational complexity** | High — certificate lifecycle management | Low — standard database operations |
| **Expressiveness** | Limited to name resolution + tag intersection | Full Datalog |
| **Auditability** | Strong — signed certificate chain is a proof | Weak — database state at verification time is ephemeral |

---

## 4. Multiple Authorizers and Third-Party Blocks

### 4.1 Can Biscuit Have More Than One Authorizer?

In the basic Biscuit model, there is a **single authorizer** per verification: the
service that receives a request, constructs an `Authorizer` instance, loads the
token, injects ambient facts, and evaluates policies. The authorizer is a *role*,
not a fixed component — different services can independently authorize the same
token because they all share the root public key.

However, Biscuit v3.2 introduced **third-party blocks**, which fundamentally
expand the trust model. Third-party blocks allow entities *other than the token's
original authority* to contribute signed facts to a token. This creates something
closer to a multi-authority model.

### 4.2 How Third-Party Blocks Work

In standard Biscuit, only facts from the **authority block** (signed by the root
key) and the **authorizer itself** are trusted by default. Blocks added by
intermediate parties can only add checks — they can restrict but never extend
what the token can do. This is the monotonic attenuation guarantee.

Third-party blocks break this restriction in a controlled way. A third-party block
is signed by an **external keypair** (not the root key), and the authorizer can
explicitly choose to trust facts from blocks signed by specific keys:

```datalog
// Standard rule — only trusts authority block and authorizer
right($resource, $op) <- role($role), role_right($role, $resource, $op);

// Rule that also trusts a third-party block signed by a specific key
group($user, $group) <- member($user, $group)
  trusting ed25519/a]bf1cb...;  // trust facts from blocks signed by this key
```

The Biscuit documentation describes the cross-domain scenario clearly: a login
service can mint a token granting access to a file repository, but only if the
holder is part of a specific group in an external social network service. The
social network service can append a signed third-party block attesting to group
membership, and the file repository's authorizer can verify both the root
signature and the third-party signature.

### 4.3 Scope Annotations

The trust model is granular. Authorizer policies and rules can specify exactly
which sources of facts they trust:

```datalog
// Default — only authority block and authorizer
f($x) <- g($x) trusting authority;

// Trust a specific external key
f($x) <- g($x) trusting ed25519/abc123...;

// Trust all previous blocks (including untrusted ones — use with caution)
f($x) <- g($x) trusting previous;
```

This means the authorizer retains full control over which third parties it
trusts and for which specific rules. Trust is never implicit — it must be
explicitly declared in each rule or policy that consumes third-party facts.

### 4.4 Does This Make Biscuit More Like SDSI?

**Partially, yes.** Third-party blocks move Biscuit toward SDSI's distributed
certificate model in several important ways:

**Similarities to SDSI:**

- **Cryptographic attribution.** A third-party block signed by key K is a
  cryptographically verifiable assertion that K made those claims. This is
  analogous to SDSI's name certificates — signed assertions by specific keys.

- **Evidence travels with the token.** The third-party block is embedded in the
  token itself, not looked up from a database. The verifier doesn't need to contact
  the third party at verification time, just as a SPKI verifier doesn't need to
  contact the name certificate issuer.

- **Multi-domain authority.** Multiple parties can contribute authoritative facts
  to a single authorization decision, each signing their contribution with their
  own key. This is the core SDSI pattern — distributed, independently-signed
  assertions composed at the point of authorization.

- **Anyone can be a "certifier."** Any entity with a keypair can sign a
  third-party block. If the authorizer chooses to trust that key, the entity
  effectively becomes a participating authority. This mirrors SDSI's model where
  any key holder can issue name certificates, and verifiers choose which issuers
  to trust via their ACL.

**Remaining differences from SDSI:**

- **Scoping is authorizer-controlled, not certificate-controlled.** In SDSI,
  the authorization chain itself determines what's valid — the verifier reduces
  the chain and either arrives at a valid 5-tuple or doesn't. In Biscuit, the
  authorizer *chooses* which third-party keys to trust in each rule. The same
  third-party block might be trusted for group membership facts but not for
  permission grants. SDSI has no equivalent of this per-rule scoping.

- **No naming layer.** SDSI's local names — the ability for K_org to define
  "engineering" as a pointer to other keys — have no equivalent in Biscuit's
  third-party blocks. Third-party blocks carry Datalog facts, not name bindings.
  There's no namespace concept and no name-resolution algebra.

- **Monotonic attenuation is still the default.** SDSI certificates can extend
  authorization through name resolution — a name cert can *add* a key to a group,
  expanding the set of authorized principals. Biscuit's third-party blocks can
  only contribute facts if the authorizer explicitly opts in via `trusting`
  annotations. The default remains closed — non-authority blocks cannot affect
  authorizer policies.

- **No chain reduction.** SDSI's 4-tuple reduction is an algebraic operation on
  certificate chains — composing name definitions through string rewriting.
  Biscuit has no equivalent composition algebra; third-party facts are simply
  loaded into the Datalog engine alongside everything else.

### 4.5 The Architectural Spectrum

The result is that Biscuit with third-party blocks sits between the two extremes:

```
Fully centralized          Biscuit (basic)     Biscuit (3rd-party)      SDSI
(server-side DB)            (single authority   (multiple signers,       (all evidence
                            + authorizer        authorizer-scoped        in cert chain,
                            facts)              trust)                   verifier reduces)
◄──────────────────────────────────────────────────────────────────────────────────►
Less distributed                                                     More distributed
```

Third-party blocks give Biscuit the *option* of distributed attestation when needed,
while preserving the simplicity of centralized authorization as the default. SDSI,
by contrast, was designed from the ground up for decentralized certificate chains
and has no centralized mode — every authorization decision involves chain reduction.

---

## 5. Integrating SDSI-Style Signed Assertions with Biscuit

### 5.1. The Missing Piece: Authorizer State Management

Biscuit's specification focuses almost exclusively on the **token lifecycle**:
minting authority blocks, attenuating with checks, appending third-party blocks,
verifying signatures, evaluating Datalog. The authorizer side is treated as a
black box — "add facts, add policies, run the engine." How those facts and
policies get into the authorizer, how they're managed over time, and who is
authorized to change them are left entirely to the application.

This is a significant gap. In every production authorization system, the
operational reality separates into two tiers with very different change
frequencies:

- **Policy rules** — change infrequently (quarterly, during security reviews),
  authored by security architects, subject to careful review:

  ```
  allow if
    group($user, "engineering"),
    resource($r),
    owner($r, "engineering"),
    operation("read")
  ```

- **Group/role assignments** — change frequently (daily, as people join/leave
  teams), managed by team leads or HR systems:

  ```
  group("alice", "engineering")
  group("bob", "engineering")
  ```

In LDAP/AD + RBAC, this separation is structural: role definitions vs.
user-to-role bindings. Kubernetes has it: ClusterRole definitions vs.
RoleBinding resources. AWS IAM has it: policy documents vs. policy
attachments. In Biscuit, both are syntactically identical Datalog — nothing
in the model distinguishes a policy rule from a group assignment.

### 5.2. Separating Verification from Trust

Most authorization systems treat signature verification as a gate
with two outcomes: pass → accept the claim, fail → reject it. The
claim either enters the system fully trusted, or it doesn't enter at
all. Trust is baked into the verification step — you only verify
against keys you already trust, so verification *is* the trust
decision.

The integration of SDSI-style signed assertions with Biscuit's
authorizer model rests on inverting this conflation. Split what most
systems do in one step into three distinct operations:

1. **Verification** (mechanical): Is this signature mathematically
   valid for this public key? Yes → store the raw tuple. No → discard.
   No judgment about whether the key is trusted, whether the claim is
   relevant, or whether the signer is authorized to make this kind of
   assertion. Just: is the math correct?

2. **Storage** (append-only): Every cryptographically valid assertion
   enters the database as a raw tuple preserving its provenance:
   `(signing-key, claim-type, ...claim-data..., t-issued, t-expires)`.
   The temporal bounds are part of what the signer cryptographically
   committed to — not metadata added at ingestion. The assertion layer
   is a factual record of "things that were cryptographically said" —
   inert data, not yet participating in any authorization decision.

3. **Trust** (Datalog rules): Trust roots and derivation rules
   determine which stored assertions are *activated* — promoted from
   raw tuples to derived facts that participate in authorization
   evaluation. An assertion from an untrusted key sits in the database
   doing nothing. It's cryptographically valid but operationally inert.

This reconciles rather than opposes the SDSI and Biscuit models.
SDSI's signed certificates provide the **ingestion mechanism** — how
assertions arrive. Biscuit's authorizer-side facts provide the
**runtime representation** — derived facts that rules produce by
joining raw assertions against trust roots. Same information, different
lifecycle phases, with a clean layer boundary between them.

### 5.3. Verification is Mechanical, Trust is Datalog

Section 5.2 describes the operational split. The deeper principle is:

> **Every interesting trust question is a rule, not a code path.**

Traditional systems encode trust decisions in application logic: "if
the key is in this list, accept the claim." Changing trust requires
changing code, configuration files, or at best a privileged database
write that lives outside the policy engine. The trust decision is
opaque to the authorization model.

In the three-layer model, trust is *data inside the same Datalog
engine*. Trust roots are facts. Trust scoping is rules. Trust
decisions are derivations. This means:

**"Do I trust this key for group assertions?"** → A fact:
`naming_authority(pk1)` in the trust root layer.

**"Do I trust this key for policy changes?"** → A fact:
`policy_authority(pk2)` in the trust root layer.

**"Is this assertion still within its validity window?"** → Part of
every derivation rule, since assertions carry their own temporal bounds:

```datalog
member($name, $key) <-
  assertion($pk, $name, $key, $issued, $expires),
  naming_authority($pk),
  time($now),
  $now >= $issued,
  $now <= $expires
```

**"Do I trust this key only for assertions about a specific domain?"**
→ A rule with an additional constraint:

```datalog
member($name, $key) <-
  assertion($pk, $name, $key, $issued, $expires),
  naming_authority($pk),
  authority_scope($pk, $domain),
  name_in_domain($name, $domain),
  time($now),
  $now >= $issued,
  $now <= $expires
```

**"Do I trust this key only during a specific window?"** → A rule
constraining the *authority's* validity (distinct from the assertion's
own validity — the authority may be trusted only temporarily, e.g.
during an incident delegation):

```datalog
member($name, $key) <-
  assertion($pk, $name, $key, $issued, $expires),
  naming_authority($pk),
  authority_valid_from($pk, $from),
  authority_valid_until($pk, $until),
  time($now),
  $now >= $from,
  $now <= $until,
  $now >= $issued,
  $now <= $expires
```

Every constraint that would traditionally require custom verification
logic becomes a Datalog rule — inspectable, composable, auditable,
and modifiable without code changes.

#### 5.3.1. Operational Consequences

The consequences of making trust a Datalog-layer concern are
significant:

**Revoking trust does not require finding individual assertions.**
Remove a trust root — `retract naming_authority(pk1)` — and every
derivation from that key vanishes instantly. The join no longer
matches. No scanning for "all assertions signed by pk1," no deletion
cascade, no race condition between revoking and evaluating. The raw
assertions remain in the database (they are historical facts — key
pk1 *did* say those things), but they produce no derived facts and
therefore participate in no authorization decisions.

**Establishing trust retroactively activates historical assertions.**
Suppose the database already contains 500 assertions from a key that
was not yet trusted. Adding `naming_authority(pk_new)` to the trust
roots immediately activates all 500 — the rules now match, derivations
appear. No re-ingestion, no replay. The assertions were waiting inertly
for a trust root to activate them.

**Auditing is trivial.** The raw assertion layer is a complete record
of everything any key ever claimed, regardless of whether it was trusted
at the time. "Why does Alice have access to engineering resources?" →
query the derivation chain. "What would change if we revoked trust in
key pk1?" → evaluate the rules with that trust root removed and diff
the derived facts.

**Trust changes are atomic.** A single fact insertion or retraction —
one Datalog operation — can activate or deactivate an entire class of
assertions. No multi-step process, no inconsistent intermediate states.

#### 5.3.2. Trust Root Key Rotation

The inert-assertion model gives a natural answer to a problem that
most systems handle awkwardly: rotating a trust root key without
service interruption.

The procedure is:

1. The new key `pk_new` signs all the same assertions that `pk_old`
   had previously signed. These new assertions enter the database as
   raw tuples attributed to `pk_new`. The old assertions from `pk_old`
   remain alongside them — both sets coexist inertly.

2. Add the new trust root: `naming_authority(pk_new)`. Immediately,
   all assertions from `pk_new` activate. The system now derives facts
   from *both* `pk_old` and `pk_new` — redundantly, but correctly.
   No gap in coverage.

3. Remove the old trust root: `retract naming_authority(pk_old)`.
   All assertions from `pk_old` go inert. Only `pk_new` assertions
   remain active.

At no point was there a window where assertions were neither trusted
under the old key nor the new key. The overlap in step 2 guarantees
continuity. And because the raw assertions from `pk_old` are never
deleted — only deactivated — the full provenance history is preserved
for audit.

Compare this to certificate-based key rotation, which typically
requires reissuing all certificates, distributing them to all relying
parties, and coordinating a cutover window during which both old and
new certificates must be accepted. Here, the "distribution" happened
asynchronously (step 1), the activation is a single fact insertion
(step 2), and the deactivation is a single fact retraction (step 3).
The coordination problem dissolves.

#### 5.3.3. Event Sourcing Analogy

The three-layer model is essentially **event sourcing applied to
trust**:

- **Raw assertions** are events — immutable records of what was said,
  by whom, and when.
- **Trust roots** are projection configuration — which event sources
  to include in the current view.
- **Derived facts** are the current projection — the materialized
  state that the authorization engine evaluates against.

Changing the projection configuration (trust roots) produces a
different materialized view (derived facts) from the same underlying
events (assertions). The events are never mutated or deleted. The
projection can be recomputed at any time from the current trust
configuration and the full event history.

This analogy extends naturally: you could maintain multiple
projections (different trust configurations for different evaluation
contexts), replay assertions against historical trust configurations
("what would this authorization decision have been last Tuesday?"),
or snapshot projections for performance while keeping the full event
log for audit.

### 5.4. The Authorizer's DB as a Policy-Controlled Resource

The next step is recognizing that the authorizer's fact database is itself a
resource. Adding a new group membership assertion, modifying a policy rule,
or removing a trust anchor are all write operations on that resource. And
write operations on resources are exactly what authorization systems control.

This leads to a recursive but non-circular model: **use the same Biscuit
policy engine to authorize changes to the authorizer's own database**.

The potential concern is a bootstrap problem or self-reference problem, but
neither applies:

**Bootstrap**: You need initial facts/policies to evaluate whether to accept
new facts. This is the root authority block — the trust anchors and seed
policies that exist before any claims are ingested. Every system has this:
Unix has root, databases have initial GRANTs, Kubernetes has the initial
cluster-admin binding. The root authority block is the genesis state. It is
not evaluated; it is trusted by construction.

**Self-reference**: The policy engine reads current state to decide whether
to accept a new fact. This is not circular as long as evaluation operates on
the current state, not the state-being-modified. This is simply a database
with access control on writes — SQL has been doing exactly this with
GRANT/REVOKE forever.

### 5.5. Multiple Trust Roots for Different Assertion Types

Extending the model, the authorizer can maintain multiple trust roots, each
scoped to a particular type of assertion:

```clojure
;; Trust anchors (genesis state — not evaluated, trusted by construction)
trust_root("group-authority-key",  "group-membership")
trust_root("policy-authority-key", "policy-rule")
trust_root("audit-authority-key",  "audit-config")

;; Meta-policy: who can add group memberships?
allow if
  operation("add-fact"),
  fact_type("group-membership"),
  issuer($key),
  trust_root($key, "group-membership"),
  signature_valid()

;; Meta-policy: who can modify policy rules?
allow if
  operation("add-rule"),
  issuer($key),
  trust_root($key, "policy-rule"),
  signature_valid()
```

This naturally expresses the two-tier separation:

- A **group manager** can sign assertions that add or remove people from
  their group, but cannot touch the policy rules that determine what group
  membership grants.
- A **policy administrator** can sign assertions that restructure permission
  rules, but cannot manage individual group memberships.
- Each operates within their scoped authority, using the same Datalog
  evaluation pipeline.

### 5.6. Minimal Authorizer Bootstrap

Taking this to its logical conclusion, an authorizer can start with almost
nothing — just the rules for trusting trust roots within their context:

1. **Genesis state**: Only meta-policies that define which keys are trusted
   for which assertion types. No application-level policy rules, no group
   memberships.

2. **Policy rules arrive**: A policy authority signs and pushes policy rules.
   The authorizer verifies the signature, evaluates acceptance against its
   meta-policy, and ingests the rules as self-asserted facts.

3. **Group assignments arrive**: A group authority signs membership
   assertions. Same pipeline — verify, evaluate, ingest.

4. **The authorizer is now fully populated** and can evaluate application
   requests using the ingested policies and memberships.

5. **Dynamic updates**: New group assignments, policy modifications, and
   even trust root rotations all flow through the same pipeline. The
   authorizer's state evolves over time, with every mutation
   authorized by the current state.

This means the authorizer is not a special privileged component with hardcoded
behavior — it's a policy engine with a seed state, and all mutations to that
state go through the same evaluation pipeline. The only special thing is the
genesis block, and that's unavoidable in any trust system.

### 5.7. Considerations

#### 5.7.1. Conflict Semantics Under Multiple Trust Roots

The three-layer model deliberately supports multiple trust roots with
overlapping scope (Section 5.5). This creates a question that pure
Biscuit never faces: **what happens when two trusted authorities assert
contradictory facts?**

Datalog is monotonic — facts accumulate, they are never retracted by
other facts. If authority A asserts `[:role "alice" "admin"]` and
authority B asserts `[:role "alice" "viewer"]`, both become active
derived facts simultaneously. Any rule matching on role sees both.
This has different implications depending on what the facts represent:

**Permission accumulation is usually safe.** If derived permissions
accumulate monotonically, contradictory role assertions produce a
union of permissions. The allow/deny policy layer constrains the
final decision. This is the standard Datalog-over-authorization model
and works well when the policy is the authority, not the individual
facts.

**Identity and attribute assertions can be dangerous.** If two
authorities disagree about a user's clearance level, department, or
account status, monotonic accumulation means the system silently
believes both. A rule granting access to "top-secret" resources
based on `[:clearance "alice" "top-secret"]` fires regardless of
whether another authority simultaneously asserts
`[:clearance "alice" "confidential"]`.

**Design options** (to be chosen based on use case):

- **Monotonic accumulation only (default).** Accept that facts
  accumulate. Rely on the policy layer (allow/deny rules) to make
  the final decision. This is the simplest model and matches standard
  Datalog semantics. Appropriate when trust roots have non-overlapping
  domains (one authority for groups, another for policies).

- **Scoped authority domains.** Trust roots are authorized only for
  specific fact predicates. Authority A can assert `[:group ...]` but
  not `[:clearance ...]`; authority B can assert `[:clearance ...]`
  but not `[:group ...]`. Conflicting assertions from the same domain
  come from the same authority, which is an authority-side bug, not a
  system design problem. This is enforceable through the meta-policy
  rules in Section 5.5.

- **Priority-based override.** Assign priority to trust roots. When
  two authorities assert facts with the same predicate and subject,
  only the higher-priority assertion activates. This breaks monotonic
  Datalog semantics and requires engine modification — derivation
  rules would need to suppress lower-priority facts.

- **Deny-overrides.** Any denial assertion from any trusted authority
  overrides all positive assertions. This is a conservative model
  suitable for high-assurance environments but can create
  denial-of-service risks if any trusted authority can unilaterally
  block access.

The recommended starting point is **scoped authority domains** —
trust roots that are authorized for specific assertion types, with
the meta-policy enforcing non-overlapping scope. This avoids the
conflict problem structurally rather than requiring resolution
machinery. Priority-based override and deny-overrides can be added
as policy-layer rules if specific use cases demand them.

#### 5.7.2. Freshness, Revocation, and Assertion Lifecycle

Once a signed claim is stored as a raw assertion, the authorizer has
no automatic mechanism to detect that the claim should no longer hold.
This is not merely an operational concern — it is a core design
question that must be addressed in the assertion format itself.

The three-layer model handles **trust root revocation** cleanly:
removing a trust root deactivates all assertions from that key. But
trust root revocation is a blunt instrument. The harder problem is
**individual assertion staleness**: a group authority's key is still
trusted, but Alice left engineering last week.

**Assertions carry their own validity.** The cleanest solution is to
make temporal bounds an integral part of the assertion tuple — not
companion metadata bolted on after the fact, but part of what the
signer cryptographically commits to:

```clojure
[:assertion pk "engineering" key-alice t-issued t-expires]
```

The derivation rule checks validity as part of the join:

```datalog
member($name, $key) <-
  assertion($pk, $name, $key, $issued, $expires),
  naming_authority($pk),
  time($now),
  $now >= $issued,
  $now <= $expires
```

One tuple, one rule, no coordination problem. The signer controls
freshness: "I, authority pk, assert that key-alice is in engineering,
and this assertion is valid from T1 to T2." The temporal bounds are
part of the claim. The authority's operational tempo is encoded in
the assertion, not in the authorizer's configuration.

This has several properties that fall out naturally:

**Expired assertions go inert automatically.** Once `$now > $expires`,
the derivation rule stops matching. No retraction, no cleanup process,
no TTL-checking daemon. The assertion stays in the DB as a historical
fact, but produces no derived facts. Same pattern as trust root
removal, but driven by time rather than by explicit retraction.

**Re-signing is the refresh mechanism.** When an assertion approaches
expiry, the authority signs a fresh one with updated timestamps. The
new assertion enters the DB alongside the old one. While both are
within their validity windows, derivations are redundant (same derived
fact from two source assertions). When the old one expires, only the
new one remains active. Zero-downtime refresh — same pattern as trust
root key rotation (Section 5.3.2).

**Revocation becomes "don't re-sign."** For many use cases, short-lived
assertions with periodic re-signing *are* the revocation mechanism. If
Alice leaves engineering, the group authority simply stops re-signing
her membership assertion. Within one validity period, her membership
expires. No revocation list, no explicit retraction, no coordination.
The validity period is the revocation window — choose it based on
tolerance for stale access.

**TTL attenuation.** The validity window on assertions is subject to
the same attenuation principle as permissions: it can only shrink,
never grow, as delegation extends. If a token carries a 24-hour group
assertion, the token holder can attenuate it for a specific operation
that takes seconds:

```clojure
;; Original assertion: valid for 24 hours
[:assertion pk "engineering" key-alice t0 (+ t0 86400000)]

;; Attenuated check: tighten to 30-second window
{:id    :short-lived
 :query [[:time ?t]]
 :when  [(<= ?t (+ t-now 30000))]}
```

This is the temporal equivalent of permission narrowing. A broad
membership assertion gets scoped to the minimum window needed for the
immediate operation. If the authorized operation on a resource requires
seconds rather than days, the attenuated token reflects that — reducing
exposure if the token is intercepted or leaked.

The authority decides the maximum validity; the token holder decides
the operational validity; the authorizer evaluates both. Permissions
shrink, validity shrinks, same principle throughout.

**Absolute timestamps over relative TTLs.** The tuple carries absolute
timestamps (`t-issued`, `t-expires`) rather than a relative TTL
(`t-issued`, `ttl-seconds`). Absolute is better for the Datalog rule —
the comparison is a direct `<=` against `time($now)`, no arithmetic
needed. The signer computes the absolute expiry from their intended
validity period at signing time.

**Explicit revocation for immediate invalidation.** Short-lived
assertions handle routine lifecycle (people joining and leaving teams).
But "fired for cause, revoke immediately" needs a mechanism that
doesn't wait for expiry. This is inherently ugly — every revocation
system is, because you're trying to un-say something that was
cryptographically said.

The least-ugly option in the three-layer model is a revocation fact
that the derivation rules check. Stroopwafel's existing `:kind :reject`
(deny rule) machinery provides this without extending Datalog with
negation-as-failure:

```clojure
;; Authorizer ingests a revocation assertion (also signed, also verified)
[:revoked pk "engineering" key-alice t-revoked]

;; A reject check prevents the membership from being used
{:kind   :reject
 :id     :check-not-revoked
 :query  [[:revoked ?pk ?name ?key ?t]]
 :when   [(= ?pk pk) (= ?name "engineering") (= ?key key-alice)]}
```

This is not elegant — revocation never is. But it's consistent with
the model (revocations are themselves signed assertions from trusted
authorities, ingested through the same pipeline), and it's the
exception rather than the rule when assertions are short-lived by
default.

**Practical revocation architecture: sensitivity-tiered checking.**
The most practical revocation mechanism for production systems is a
real-time revocation service that receives signed revocation
certificates and makes revocation information available as a
queryable service. The key design decision is how often the
authorizer checks it — and the answer is: it depends on what the
authorizer is authorizing.

Not every policy evaluation warrants a synchronous revocation check.
Checking a revocation service on every request adds latency and
creates an availability dependency — exactly the kind of runtime
dependency that Biscuit's offline verification model was designed to
eliminate. But ignoring revocation entirely creates an unbounded
exposure window.

The resolution is **sensitivity-tiered revocation checking**: label
operations with sensitivity levels, and let the sensitivity determine
how fresh the revocation information must be.

```clojure
;; Sensitivity levels are facts — policy, not code
[:sensitivity "/api/financial-transfer" :critical]
[:sensitivity "/api/admin/users"        :high]
[:sensitivity "/api/reports"            :medium]
[:sensitivity "/api/status"             :low]

;; Revocation cache freshness thresholds (milliseconds)
[:revocation-max-age :critical 0]          ;; synchronous check every eval
[:revocation-max-age :high     60000]      ;; every minute
[:revocation-max-age :medium   3600000]    ;; hourly
[:revocation-max-age :low      86400000]   ;; daily
```

A `:critical` operation (financial transfer, privilege escalation)
checks the revocation service synchronously on every evaluation. A
`:low` operation (reading a status page) trusts a cached revocation
snapshot refreshed daily. The cost of revocation checking scales with
the risk of the operation, not with the volume of requests.

**Bloom filter distribution.** The revocation service maintains a
bloom filter of currently revoked assertion hashes. Authorizers
periodically fetch the current filter and cache it locally. Bloom
filter properties are ideal for revocation: "not present" means
definitely not revoked (zero false negatives — you never miss a
revocation), while "present" means possibly revoked (false positives
fail in the safe direction — treat as revoked, or do a full check
against the revocation service).

The bloom filter is compact enough for frequent distribution. An
authorizer handling low-sensitivity requests checks against its
cached bloom filter — a local, sub-microsecond operation. For
high-sensitivity requests, it does a synchronous check against the
revocation service. The filter acts as a first-pass screen that
catches the majority of revocations without network round-trips.

**Revocation as a trust-model participant.** The revocation service
itself fits the three-layer model. It is another authority that signs
assertions — specifically, revocation assertions. The authorizer
trusts it via a trust root:

```clojure
[:trust-root pk-revocation-service :revocation]
```

Revocation bloom filters are a compact projection of the revocation
service's current state, analogous to how derived facts are a
projection of the raw assertion store. Multiple revocation services
can exist for different assertion types, paralleling the scoped trust
roots for different assertion domains.

**Sensitivity levels are themselves policy.** Because sensitivity
labels and freshness thresholds are Datalog facts in the authorizer's
DB, they can be managed through the same meta-policy pipeline as
other policy rules (Section 5.4). A security architect signs
assertions that set sensitivity levels on resources; the authorizer
ingests them through the standard pipeline. Changing a resource's
sensitivity from `:medium` to `:critical` is a policy change, not a
code change — and it immediately affects revocation checking behavior
without redeploying anything.

**Recommended defaults for deployment safety.** Without concrete
defaults, every deployment invents its own TTL ranges, sensitivity
tiers, and revocation check modes. This creates fragmented security
postures and makes cross-deployment reasoning difficult. The
following defaults are recommended as a "secure by default" baseline
that deployers can override with justification:

| Assertion class | Max validity | Sensitivity | Revocation check |
|----------------|-------------|-------------|-----------------|
| Group membership | 24 hours | `:medium` | Cached bloom filter, hourly refresh |
| Role assignment | 24 hours | `:high` | Cached bloom filter, per-minute refresh |
| Policy rule | 30 days | `:high` | Cached bloom filter, per-minute refresh |
| Trust root | No expiry (explicit retraction only) | `:critical` | Synchronous check every eval |
| Session / operation grant | 1 hour | `:medium` | Cached bloom filter, hourly refresh |
| Privilege escalation | 5 minutes | `:critical` | Synchronous check every eval |

These are conventions, not engine constraints — the engine treats all
assertion tuples uniformly. But shipping sensible defaults in the
ingestion pipeline (e.g., `ingest-assertion!` rejects group
membership assertions with validity windows exceeding 24 hours unless
an override flag is set) nudges deployers toward secure configurations
without requiring them to design their own policies from scratch.

The sensitivity-to-revocation-mode mapping (`:critical` →
synchronous, `:high` → per-minute bloom filter, `:medium` → hourly,
`:low` → daily) should be the out-of-box configuration. Deployers
who need different thresholds override via signed policy assertions
through the standard meta-policy pipeline.

**Explicit relation names for the assertion lifecycle.** The three-
layer model describes three conceptual stages: raw storage, verified
integrity, trust-activated derivation. Making these distinct relation
names in the Datalog schema makes the stages queryable and auditable
without requiring knowledge of which derivation rules fired:

```clojure
;; Layer 1: cryptographically valid, stored as-is
[:assertion-raw pk "engineering" key-alice t-issued t-expires
               sig-bytes ingestion-time]

;; Layer 2: signature verified against known key format
[:assertion-verified pk "engineering" key-alice t-issued t-expires]

;; Layer 3: trust root matched, temporal validity confirmed
[:assertion-active pk "engineering" key-alice]
```

`assertion-raw` is an immutable event (append-only, never modified).
`assertion-verified` is a derived fact produced by a rule that checks
cryptographic validity. `assertion-active` is a derived fact produced
by rules that join against trust roots and check temporal bounds.

This makes incident response queries straightforward:

- "Show me everything signed by key X" → query `assertion-raw`
- "Show me everything that passed verification but isn't trusted" →
  query `assertion-verified` minus `assertion-active`
- "Show me everything currently active for user Y" → query
  `assertion-active`
- "Show me everything that was active yesterday but isn't today" →
  replay with historical `time()` fact

The three relations are not independent storage — `assertion-verified`
and `assertion-active` are Datalog derivations from `assertion-raw`.
They exist in the fact store as derived facts with origin tracking,
just like any other rule output. The naming convention makes the
lifecycle stages first-class in the schema rather than implicit in
the rule structure.

#### 5.7.3. Push vs. Pull

Does the group authority push signed assertions to authorizers, or
do authorizers pull them on demand? Push is more SDSI-like (carry
evidence with the token or broadcast to authorizers). Pull is more
traditional (query a directory service at verification time). A system
could support both — carry critical memberships in the token
(self-contained, works offline) and pull supplementary context from a
directory (always fresh, potentially large).

#### 5.7.4. Token Size vs. Freshness Trade-off

Embedding group assertions in the authority block makes the token
self-contained (like SDSI) but creates stale-membership risk. Keeping
them authorizer-side keeps tokens small and memberships current but
requires DB access. The practical sweet spot likely varies by use
case — critical, slow-changing memberships in the token; large,
frequently-changing group rosters on the authorizer side.

#### 5.7.5. Rabbit Hole Risk

If the genesis state itself required policy evaluation to install,
you'd get infinite regress — who authorizes the authorizer? The model
avoids this the same way every trust system does: the root authority
block is axiomatic. Introducing trust roots "at the right level" is
essential — too low and you get infinite regress, too high and you
get a god-key that centralizes everything you were trying to
distribute.

#### 5.7.6. Proof Wallet — Client-Side Evidence Assembly

The SDSI model places the burden of proof assembly on the client:
the prover must collect and present the right chain of certificates
to the verifier. If a user needs five signed assertions to prove
access, manually constructing that request is unworkable.

The three-layer model shifts most of this burden to the authorizer
(assertions are pre-ingested into the DB, rules derive facts
automatically). But for token-carried assertions (the hybrid model
in Section 5.7.4) or cross-organization federation, the client still
needs to know which assertions to include.

A **proof wallet** solves this: a client-side library that maintains
a local store of signed EDN assertions, indexed by subject, resource,
and issuer. When the client needs to make an authorization request,
the wallet runs a local Datalog query against its assertion store to
compute the minimal evidence set needed for the specific request, and
bundles the relevant assertions alongside the token.

This is architecturally distinct from the token itself — the token
carries attenuated capability (Biscuit-style), the wallet carries
supporting assertions (SDSI-style). The authorizer evaluates both.

In Clojure, this is a natural `cljc` library: the same Datalog engine
and CEDN serialization used by the authorizer runs client-side for
proof selection. The wallet could also cache assertion validity
(checking TTLs locally before including stale assertions) and pre-
compute which assertions are needed for common access patterns.

### 5.8. Datalog Term Types and Schema

The three-layer model (Section 5.2–5.6) assumes the authorizer's Datalog
database can store tuples like `assertion(signing-key, name, subject-key)`.
Whether this actually works depends on what the Datalog engine allows as
term values.

#### 5.8.1. Biscuit's Term Type Constraints

Biscuit defines a fixed set of term types: integers, strings, booleans,
dates, byte arrays, and sets. Public keys appear in the `trusting`
annotation syntax for scoping third-party blocks:

```datalog
check if member("group") trusting ed25519/{key}
```

But public keys are **not a term type within facts**. You cannot write:

```datalog
assertion(ed25519/{key}, "engineering", ed25519/{other_key})
```

Public keys live in the scoping/trust layer — they are metadata about
which blocks to believe, not values that can be stored in facts and
joined over. In Biscuit-as-specified, you would have to represent keys
as strings or byte arrays in fact terms, losing the type distinction
between "this is a public key" and "this is an arbitrary string." It
works mechanically — the Datalog engine happily joins over string
values — but the engine cannot enforce that a term position actually
holds a valid public key.

This is a deliberate design choice by Biscuit, not an oversight. Biscuit's
Datalog is designed for evaluating authorization policies against token
contents, not for managing authorizer state with cryptographic provenance.
The `trusting` mechanism handles the "trust a specific key" use case at
the scope level, which is sufficient for token-side verification but not
for the authorizer-side assertion model described here.

#### 5.8.2. Stroopwafel's Advantage: Untyped EDN Tuples

Stroopwafel's Datalog engine operates on plain EDN tuples with structural
unification. A fact is just a flat vector, and the engine matches term
positions by value equality. It does not impose a type system on terms:

```clojure
[:assertion "ed25519:abc123..." "engineering" "ed25519:def456..."]
```

Public keys are simply values — strings, byte vectors, whatever
EDN-representable form is chosen. The `unify` function in `datalog.clj`
matches them structurally via the `bind` function, which checks value
equality regardless of type. The `(signing-key, name, subject-key)`
tuples from the three-layer model work directly as facts, and Datalog
rules can join over the signing-key position exactly as described in
Section 5.6.

Stroopwafel already handles byte arrays natively through CEDN's `#bytes`
tagged literal (CEDN 1.2.0), which was specifically added for the signing
pipeline. Public keys encoded via `crypto/encode-public-key` (X.509
byte arrays) can be stored directly in fact tuples and compared via
`crypto/bytes=`, or serialized deterministically as `#bytes "hex"` for
signing and wire transmission.

This is not an accident of minimalism; it is an inherent advantage of
using a language-level data model (EDN) rather than a fixed schema model
(Protobuf). The set of representable term values is open — anything EDN
can express, the Datalog engine can store and unify over.

#### 5.8.3. Optional Schema: Design Considerations

Given that untyped tuples already work, the question is whether to
add an optional schema layer that validates fact structure at write
time. This is a pure extension — schema validation on write, invisible
during evaluation — that preserves full backwards compatibility.

**Arguments for schemas:**

- **Validation at ingestion.** Without a schema, injecting
  `[:assertion "not-a-key" 42 :oops]` into the DB succeeds silently.
  The malformed fact sits inertly — it never joins with anything useful,
  but the error is invisible until someone debugs a missing derivation.
  A schema catches this at write time with a clear error message.

- **Documentation as data.** The schema itself is a queryable fact in
  the DB: "what shapes of assertions exist?" Useful for introspection
  tooling, admin interfaces, and audit.

- **Constraint propagation.** If the engine knows the first term of
  an `assertion` fact is always a public key, it could optimize index
  selection or provide better error messages when a rule can't possibly
  match due to type mismatch.

- **Gradual adoption.** Teams that don't want schemas get the same
  engine unchanged. Teams that do get validation. Start with conventions
  (term positions by agreement), add schemas when patterns stabilize.

**Arguments against schemas:**

- **Complexity budget.** Stroopwafel's Datalog engine has grown from
  KEX's original ~120 lines to a substantial module with expression
  evaluation, scope filtering, origin tracking, and policy evaluation.
  That growth was warranted — each addition addressed a real Biscuit
  feature gap. But each further addition (schema registry, validation
  hooks) adds surface area to an authorization-critical code path.
  Schema validation is a different concern from evaluation, and mixing
  them risks making the engine harder to verify.

- **Where does the schema live?** If schemas are facts in the DB,
  they need to be in the genesis state (otherwise who authorizes adding
  a schema?). That is one more thing in the bootstrap. If they are
  outside the DB, a second kind of configuration exists alongside
  facts and rules.

- **Premature abstraction.** The three-layer model has exactly one
  tuple pattern so far: `(signing-key, name, subject-key)`. Adding a
  schema system for one tuple shape is over-engineering. The abstraction
  should emerge from discovering that multiple distinct patterns all
  need the same validation machinery.

- **False safety.** Schema validates shape, not semantics. A
  well-shaped `[:assertion valid-key "engineering" other-valid-key]`
  that is factually wrong — the signer did not actually sign this — is
  more dangerous than a malformed tuple that never joins. The real
  safety comes from signature verification before ingestion, not from
  schema checking.

#### 5.8.4. Recommended Approach

Stay with untyped tuples for now, but design the fact-ingestion API so
that a schema validation step can slot in later without changing the
engine or the DB representation.

Stroopwafel's `insert-fact` already provides this extension point — fact
insertion goes through a function, not direct DB manipulation. The
`ingest-assertion!` function proposed in Section 6.5 (Phase 7) wraps
this with signature verification and timestamp tracking. Schema
validation would be an additional step in that same pipeline:

```clojure
;; Today (Stroopwafel v0.6.0): just inserts
(insert-fact store [:assertion pk "engineering" key-alice] #{:external})

;; Phase 7: verify, then insert
(ingest-assertion! store signed-assertion)
;; internally: verify-sig → insert-fact with provenance

;; Later, if schemas earn their keep:
(ingest-assertion! store signed-assertion)
;; internally: verify-sig → validate-schema → insert-fact
```

The engine stays clean. The extension point exists. Nothing breaks.
The backwards compatibility guarantee is trivial because unschematized
facts pass through validation with no schema to check against.

### 5.9. Prior Art and Related Work

The specific pattern of using a policy engine to manage its own authorizer
state does not appear to have been explored within the Biscuit ecosystem.
However, several adjacent efforts are relevant:

**Biscuit v3 third-party blocks** (2023): The `trusting` annotation in
Biscuit's Datalog allows selectively trusting facts from blocks signed by
specific public keys. This is the closest Biscuit-native mechanism to
SDSI-style signed assertions. However, it operates entirely on the
**token side** — facts are carried in the token and scoped by block
signatures. It does not address authorizer state management or the ingestion
of signed claims into the authorizer's own database. The design discussion
(GitHub issue #88, opened by Clément Delafargue in January 2022) explicitly
frames the problem as "which blocks can we trust" within a token, not "how
does the authorizer manage its own state." Third-party blocks do enable
distributed verification across security domains — a login service can mint
a token that requires a group membership proof from a social network service,
with the proof carried as a signed block in the same token. This is
structurally similar to SDSI certificate chains (the token carries its own
evidence), but the scoping is token-local rather than authorizer-persistent.

**OPA signed policy bundles** (2020): Open Policy Agent supports
cryptographically signed bundles of policy and data files. OPA verifies
bundle signatures using a pre-configured public key before activating new
policies. This is the closest existing system to "signed policy
distribution," but it operates as a pure integrity check — OPA does not use
its own policy engine to decide whether to accept new policies. The bundle
signing is an out-of-band mechanism (RSA/ECDSA signatures over a JWT
manifest), not integrated with the Rego policy language. There is no concept
of scoped trust roots for different policy types or of using Rego rules to
authorize policy changes.

**Zanzibar / SpiceDB**: Google's Zanzibar system (and its open-source
descendants like SpiceDB and OpenFGA) separates the schema (relationship
definitions) from the relationship tuples (who has what relation to what
resource). This is structurally similar to the policy-rules vs.
group-assignments separation. However, Zanzibar manages both tiers through
a privileged API with its own access control — it does not use its own
authorization engine to authorize schema or tuple changes.

**XACML administrative policy**: The XACML specification includes a
concept of "administrative policy" — policies that govern who can create
or modify other policies. This is the closest formal precedent to the
self-referential model described here, but XACML's complexity and
XML-heaviness limited its practical adoption.

**No identified prior art** exists for the specific combination proposed
here: using Biscuit-style Datalog evaluation to authorize changes to the
authorizer's own fact database, with multiple scoped trust roots for
different assertion types, and a minimal bootstrap that grows the authorizer's
state dynamically through the same evaluation pipeline it uses for
application requests.

---

## 6. Implications for Stroopwafel

Stroopwafel v0.6.0 has achieved full Biscuit feature parity: block
isolation with set-based origin tracking, ephemeral key chains, sealed
tokens, Datalog expressions (`:when`/`:let` guards with ~35 whitelisted
built-in functions), authorizer policies (ordered allow/deny), revocation
IDs, and third-party blocks. The codebase is ~1200 lines of Clojure with
88 tests and zero dependencies beyond Clojure and CEDN.

The design questions that follow are grounded in the actual architecture
rather than in hypothetical extensions.

### 6.1. The Bridge from Current Architecture to Three-Layer Model

Stroopwafel's existing architecture is closer to the three-layer model
(Section 5.2–5.3) than it might appear. The key observation is that
`:trusted-external-keys` on the `evaluate` API is already a proto-trust-
root — the mechanism by which the authorizer decides which external signing
keys to believe:

```clojure
(stroopwafel.core/evaluate token2
  :authorizer {:trusted-external-keys [idp-pk]
               :checks [{:id    :has-email
                          :query [[:email "alice" "alice@idp.com"]]}]})
```

Currently, this trust decision is made by the caller as a configuration
parameter passed in externally. The three-layer model would generalize
this: trust roots become facts *inside* the Datalog DB, and rules derive
which assertions are active. The architectural step is moving trust from
a caller-provided parameter to an engine-internal fact.

Concretely, `:trusted-external-keys` would become:

```clojure
;; Instead of this (caller-provided):
:authorizer {:trusted-external-keys [idp-pk]}

;; The authorizer DB would contain:
[:trust-root (encode-public-key idp-pk) :identity-attestation]
```

And the scope-extension logic in `eval-token` that computes
`trusted-block-indices` from `:trusted-external-keys` would become a
Datalog rule that joins block metadata against trust root facts.

### 6.2. Fact Ingestion API as Extension Surface

The `insert-fact` function in `datalog.clj` already goes through a
function rather than direct DB manipulation:

```clojure
(defn insert-fact [store fact origin]
  (update store fact (fn [existing]
                       (if existing
                         (set/union existing origin)
                         origin))))
```

This is exactly the extension point recommended in Section 5.8.4. A
verification-then-store pipeline wraps this: verify signature →
`insert-fact` with origin tracking the signing key → let Datalog rules
handle trust activation. The engine itself does not need to change; the
ingestion API is the extension surface.

The assertion-carries-validity model (Section 5.7.2) simplifies this
further. Because temporal bounds are part of the assertion tuple
itself, the ingestion pipeline does not need to track TTLs or manage
expiry. The assertion enters the store with its `t-issued` and
`t-expires` baked in, and the derivation rules handle freshness
checking via the ambient `time()` fact. Expired assertions go inert
automatically — no retraction needed, the fact store stays append-only,
and the engine stays purely monotonic.

For explicit revocation (the exception case), revocation assertions
are themselves signed and ingested through the same pipeline. The
`:kind :reject` machinery already in Stroopwafel's Datalog engine
handles the deny logic without extending the engine with
negation-as-failure.

### 6.3. CEDN as the Uniform Data Format

SPKI/SDSI's original design relied on Canonical S-expressions (RFC 9804)
for deterministic cryptographic hashing. Biscuit uses Protobuf. Stroopwafel
uses CEDN, which provides the same deterministic serialization guarantee
while staying idiomatic in Clojure.

The advantage is more than aesthetic. Biscuit's Protobuf schema imposes a
fixed type system on Datalog terms (integers, strings, booleans, dates,
byte arrays, sets) and places public keys in a separate scoping layer
rather than in the data layer. Stroopwafel's CEDN-based engine operates on
plain EDN tuples with structural unification — a public key is just another
value the engine can store and join over. This gives Stroopwafel a natural
advantage for the three-layer assertion model, where rules must join over
signing-key positions in assertion tuples (Section 5.8).

Additionally, because Stroopwafel uses `.cljc` patterns and CEDN is
cross-platform (JVM, Babashka, nbb, shadow-cljs, Scittle), the same
serialization, hashing, and Datalog evaluation code can run on both the
authorizer (server-side) and the proof wallet (client-side). This makes
the proof wallet concept (Section 5.7.6) a natural `cljc` library rather
than a separate implementation.

### 6.4. What Stroopwafel Already Has vs. What's Needed

| Capability | Current Status | Three-Layer Model Requirement |
|------------|---------------|-------------------------------|
| Signed assertions from external parties | ✓ Third-party blocks (v0.6.0) | Generalize to authorizer-side ingestion |
| Selective trust of external keys | ✓ `:trusted-external-keys` parameter | Move trust roots into Datalog DB as facts |
| Scope-filtered fact visibility | ✓ `trusted-origins`, `facts-for-scope` | Extend to include trust-root-derived scopes |
| Origin tracking on facts | ✓ Set-based origin model (`#{0 N :authorizer}`) | Add signing-key provenance to origin metadata |
| Fact insertion via function | ✓ `insert-fact` / `insert-facts` | Add verification wrapper |
| Temporal validity | ✓ `:when` guards can check `time()` | Assertions carry `t-issued`/`t-expires` in tuple |
| Append-only fact store | ✓ No retraction | No change — expiry via derivation rules, not deletion |
| Datalog expressions | ✓ `:when`/`:let` guards, ~35 built-ins | Use for validity window checks, freshness rules |
| Authorizer policies | ✓ Ordered allow/deny | Use for meta-policy (Section 5.4) |
| Deny rules | ✓ `:kind :reject` | Use for explicit revocation checks |
| Fixpoint rule evaluation | ✓ Scoped, per-block, max 100 iterations | No change needed |
| Cross-platform | JVM only (Babashka ready) | Required for proof wallet (cljc) |

### 6.5. Recommended Implementation Sequence

The following phases build on Stroopwafel v0.6.0 and are ordered by
dependency, not priority:

**Phase 7: Signed assertion ingestion pipeline.** Add an `ingest-assertion!`
function that: (1) verifies the Ed25519 signature, (2) stores the raw
assertion tuple — including its `t-issued` and `t-expires` — with
signing-key provenance, (3) optionally validates against a schema if one
is registered for the assertion type. This wraps the existing
`insert-fact` without modifying the Datalog engine. The assertions are
inert — they don't participate in authorization until trust roots and
temporal validity activate them.

**Phase 8: Trust roots as Datalog facts.** Move `:trusted-external-keys`
from a caller-provided parameter into the authorizer's fact store as
`[:trust-root encoded-key scope-type]` facts. Add derivation rules that
join raw assertions against trust roots — and check temporal validity
against the ambient `time()` fact — to produce active facts. Deprecate
the `:trusted-external-keys` parameter in favor of trust root facts
(maintain backward compatibility during transition).

**Phase 9: Meta-policy for authorizer mutations.** Use Stroopwafel's
existing authorizer policy machinery to authorize writes to the authorizer's
own DB. The genesis state contains only trust roots and meta-policies.
Policy rules and group assignments arrive as signed assertions, verified
and ingested through the Phase 7 pipeline, activated through the Phase 8
trust roots.

**Phase 10: Explicit revocation.** Add revocation assertion support for
cases where short-lived assertions aren't sufficient (immediate
invalidation). Revocation assertions are themselves signed, ingested
through the same pipeline, and checked via Stroopwafel's existing
`:kind :reject` deny rules. The fact store stays append-only — no
retraction needed.

**Phase 11: Proof wallet (cljc).** Client-side library that maintains a
local store of signed EDN assertions, computes minimal evidence sets for
authorization requests, and bundles relevant assertions alongside tokens.
The wallet can also check validity windows locally (excluding expired
assertions before including them) and attenuate TTLs for specific
operations. Shares Datalog engine and CEDN serialization with the
authorizer.

**Phase 12: Conflict resolution policies.** If use cases emerge that
require multiple trust roots with overlapping assertion domains, add
priority-based override or deny-overrides as policy-layer rules
(Section 5.7.1).

### 6.6. What Stroopwafel Contributes Beyond Biscuit

Biscuit specifies token lifecycle comprehensively but leaves authorizer
state management unaddressed. Stroopwafel's proposed extensions would
provide:

- **A principled answer to "how do facts get into the authorizer?"** —
  signed assertion ingestion with cryptographic provenance, not opaque
  database writes.

- **Separation of policy rules from group assignments** — structural,
  not just conventional, enforced through scoped trust roots and
  meta-policy.

- **Seamless trust root rotation** — the inert-assertion model
  (Section 5.3.2) eliminates the coordination problem that plagues
  certificate-based key rotation.

- **Event-sourced audit trail** — raw assertions are immutable events,
  trust roots are projection configuration, derived facts are the
  current materialized view (Section 5.3.3).

- **Uniform data format from token to authorizer to wallet** — CEDN
  throughout, no Protobuf/EDN impedance mismatch, `cljc` code sharing
  between server and client.

These are not theoretical extensions — they build directly on
Stroopwafel's existing architecture (set-based origin tracking, scoped
rule evaluation, third-party block trust, CEDN serialization) and
require no changes to the core Datalog evaluation engine.

---

## Sources

### SPKI/SDSI

- **RFC 2692** — SPKI Requirements (Ellison, September 1999)
  https://www.rfc-editor.org/rfc/rfc2692
- **RFC 2693** — SPKI Certificate Theory (Ellison, Frantz, Lampson, Rivest, Thomas, Ylonen, September 1999)
  https://www.rfc-editor.org/rfc/rfc2693
- **RFC 9804** — Simple Public Key Infrastructure (SPKI) S-Expressions (June 2025)
  https://www.rfc-editor.org/rfc/rfc9804
- **SPKI Certificate Structure Draft** (Ellison et al., 1998)
  https://datatracker.ietf.org/doc/html/draft-ietf-spki-cert-structure-05
- **Carl Ellison's SPKI page** — documentation, code, and references
  https://theworld.com/~cme/html/spki.html
- **Certificate Chain Discovery in SPKI/SDSI** (Clarke, Elien, Ellison, Fredette, Morcos, Rivest)
  https://people.csail.mit.edu/rivest/pubs/CEEFx01.pdf
- **Understanding SPKI/SDSI Using First-Order Logic** (Li, Mitchell — Stanford)
  http://theory.stanford.edu/people/jcm/papers/sem_spki_j.pdf
- **A Logical Reconstruction of SPKI** (Halpern — Cornell)
  https://cgi.cse.unsw.edu.au/~meyden/research/spkij.pdf
- **Trust Management Languages** (Li, Mitchell — used as Biscuit reference)
  https://www.cs.purdue.edu/homes/ninghui/papers/cdatalog_padl03.pdf
- **IETF SPKI Working Group charter**
  https://datatracker.ietf.org/wg/spki/about/
- **Go SPKI implementation** (eadmund)
  https://github.com/eadmund/spki

### Biscuit

- **Biscuit specification** (Couprie et al.)
  https://doc.biscuitsec.org/reference/specifications
- **Biscuit introduction**
  https://doc.biscuitsec.org/getting-started/introduction
- **Authorization policies**
  https://doc.biscuitsec.org/getting-started/authorization-policies
- **Datalog reference** (including scope annotations and third-party trust)
  https://doc.biscuitsec.org/reference/datalog
- **Third-party blocks: why, how, when, who?** (Biscuit blog)
  https://www.biscuitsec.org/blog/third-party-blocks-why-how-when-who/
- **Eclipse Biscuit project**
  https://github.com/eclipse-biscuit/biscuit
- **Biscuit website**
  https://biscuitsec.org
- **Introduction to Biscuit** (Clever Cloud engineering blog, April 2021)
  https://www.clever.cloud.com/blog/engineering/2021/04/12/introduction-to-biscuit/
- **Biscuit Authorization tutorial** (Space and Time)
  https://www.spaceandtime.io/blog/biscuit-authorization
- **Block scoping and third-party caveats** (GitHub issue #88)
  https://github.com/eclipse-biscuit/biscuit/issues/88
- **Hacker News discussion** (December 2023)
  https://news.ycombinator.com/item?id=38635617
- **Biscuit 3.0 release** (third-party blocks, `trusting` annotations)
  https://www.biscuitsec.org/blog/biscuit-3-0/
- **Public key confusion in third-party blocks** (Security advisory, 2024)
  https://github.com/eclipse-biscuit/biscuit/security/advisories/GHSA-rgqv-mwc3-c78m
- **Delegation in microservices** (Biscuit documentation)
  https://www.biscuitsec.org/docs/guides/microservices/

### Stroopwafel

- **Stroopwafel repository** (Frank Siebenlist)
  Capability-based authorization tokens for Clojure, derived from KEX
  with CEDN serialization and full Biscuit feature parity (v0.6.0).
- **CEDN (Canonical EDN)** (Frank Siebenlist)
  https://github.com/franks42/canonical-edn
  Deterministic EDN serialization — Stroopwafel's wire format.

### KEX

- **KEX repository** (Seref Ayar)
  https://github.com/serefayar/kex
- **"Reconstructing Biscuit in Clojure"** (Ayar, February 2026)
  https://serefayar.substack.com/p/reconstructing-biscuit-in-clojure

### Background

- **Macaroons: Cookies with Contextual Caveats** (Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner — Google, 2014)
  https://ai.google/research/pubs/pub41892
- **Distributed Certificate-Chain Discovery in SPKI/SDSI** (Schwoon et al.)
  https://research.cs.wisc.edu/wpis/papers/TR1526.pdf
- **Anonymous Credentials: An Illustrated Primer** (Matthew Green, March 2026)
  https://blog.cryptographyengineering.com/2026/03/02/anonymous-credentials-an-illustrated-primer/
  Blind signatures, ZK selective disclosure, N-time-use credentials, banlist
  revocation. Complementary to capability tokens — anonymous credentials
  address unlinkability at the consumer-facing edge (proving eligibility
  without revealing identity), while capability tokens like Stroopwafel
  handle the named authorization chain behind that edge.

### Adjacent Systems (Policy Management)

- **OPA Bundle Signing** — signed policy bundles for integrity verification
  https://www.openpolicyagent.org/docs/management-bundles
- **OPA Discovery** — centralized configuration management for OPA instances
  https://www.openpolicyagent.org/docs/management-discovery
- **Zanzibar: Google's Consistent, Global Authorization System** (Pang et al., USENIX ATC 2019)
  https://research.google/pubs/pub48190/
- **SpiceDB** — open-source Zanzibar implementation (AuthZed)
  https://github.com/authzed/spicedb
- **OpenFGA** — open-source Zanzibar-inspired authorization (Auth0/Okta)
  https://openfga.dev
- **Topaz Policy Lifecycle** — OPA-based policy lifecycle management
  https://www.topaz.sh/docs/policies/lifecycle
