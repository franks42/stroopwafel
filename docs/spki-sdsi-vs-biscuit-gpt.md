# SPKI/SDSI vs Biscuit — Notes for Stroopwafel

## Second-pass update (after re-read)

The latest draft now addresses most of the concerns from my first review.

- **Conflict semantics** are now explicitly covered in Section 5.7.1, including domain scoping, priority, and deny-override alternatives.
- **Freshness/revocation** is now treated as first-class in Section 5.7.2 (time-bounded assertions, re-signing lifecycle, immediate revocation path, and sensitivity-tiered checks).
- **Usability/proof assembly** is now addressed directly in Section 5.7.6 via a `cljc` proof-wallet approach.

Net: this is materially stronger and much closer to an implementable architecture for Stroopwafel.

## Overall take

The document is strong and the core observation is right: SPKI/SDSI and Biscuit are not opposites; they are different points in a design space.

- SPKI/SDSI optimizes for **portable, signed evidence** and decentralized verification.
- Biscuit optimizes for **policy expressiveness and operational simplicity** at the authorizer.
- Stroopwafel can combine both by treating signed assertions as ingestible EDN data and using Datalog to decide trust activation.

That combination is especially natural in Clojure.

## What I agree with most

1. **The three-layer split (verify -> store -> trust) is the key architectural insight.**
   This cleanly separates cryptographic validity from authorization semantics. It also gives clear operational handles for key rotation, trust revocation, and auditability.

2. **Authorizer-state management is the under-specified gap in Biscuit-like systems.**
   Biscuit handles token semantics very well, but says little about who may mutate group/policy data at runtime. Your proposal to authorize these writes using the same Datalog engine is compelling.

3. **Untyped EDN tuples are a practical advantage for Kex/Stroopwafel.**
   Storing signer identifiers as regular terms and joining over them is straightforward in EDN. You avoid forced encoding gymnastics.

4. **Third-party blocks are a useful bridge, not a full SDSI replacement.**
   The document correctly calls out that Biscuit’s `trusting` scoping is authorizer-controlled and lacks SDSI’s naming algebra.

## Where I’d sharpen the model

- **Revocation/freshness scope is now strong; define mandatory defaults.**
   The design now covers lifecycle deeply. I’d still lock in concrete defaults (for example: max assertion validity by class, default sensitivity tiers, and required revocation check mode per tier) so deployments don’t drift into insecure variance.

- **Distinguish provenance from authorization facts explicitly.**
  Consider separate relations like:
  - `assertion_raw(...)` (immutable event)
  - `assertion_verified(...)` (crypto check passed)
  - `assertion_active(...)` (trusted by current policy)
   This keeps audits and incident response clear. The document now discusses provenance well; this suggestion is mainly to make the data model unambiguous in implementation.

- **Conflict semantics are covered; add one operational tie-break policy.**
   The alternatives are now well explained. I’d add a single recommended operational default for production (for example: scoped authority domains + deny on out-of-scope predicate assertions) to reduce ambiguity for adopters.

## Usability view for Stroopwafel

Adding SPKI/SDSI-like properties makes sense **if the UX defaults remain Biscuit-simple**.

### Good defaults (recommended)

- Default mode: **single-authority Biscuit-like flow** (easy to adopt).
- Optional mode: **signed external assertions** (SDSI-like) for federation/high-assurance contexts.
- Keep app developers on a short path: write Datalog, inject request context, evaluate policy.

### Main usability risk

The classic SDSI problem is proof assembly burden on the client. If users must manually collect and chain assertions, adoption suffers.

### Mitigation in Clojure/cljc

Build a `cljc` “proof wallet” layer that:

- stores signed EDN assertions,
- indexes by subject/resource/issuer,
- computes a minimal relevant evidence set for a query,
- emits a compact token bundle.

With this, you preserve decentralized evidence without exposing chain mechanics to most users.

## Canonical-EDN implications

This project direction is strong:

- Canonical-EDN gives deterministic serialization for signatures while staying idiomatic in Clojure.
- You avoid a split mental model (policy in Datalog, payload in Protobuf, glue in ad hoc codecs).
- `cljc` lets verifier/prover share data model, canonicalization, and rule logic.

That is a material practical advantage over many Biscuit deployments.

## Suggested incremental roadmap

1. **Phase 1: solid single-authority core**
   Token verification, attenuation, authorizer policies, ambient context.

2. **Phase 2: signed assertion ingestion pipeline**
   Verify signatures -> store immutable raw assertions -> derive trusted active facts.

3. **Phase 3: meta-policy for DB mutations**
   Use Datalog rules to authorize who can add/retract memberships, policies, trust roots.

4. **Phase 4: external/federated assertions**
   Add SDSI-like distributed attestations and optional token-carried evidence.

5. **Phase 5: optional schema-on-ingest**
   Keep engine untyped; add validation hooks at ingestion API only if needed.

## Bottom line

Yes—adding SPKI/SDSI-like properties is worthwhile for Stroopwafel, but as an **opt-in distributed trust layer** on top of a Biscuit-like default.

The strongest strategy is:
- keep runtime authorization simple and Datalog-centric,
- make signed assertions portable and auditable via canonical EDN,
- hide distributed-proof complexity behind `cljc` tooling.

That gives you better federation and auditability without sacrificing everyday usability.