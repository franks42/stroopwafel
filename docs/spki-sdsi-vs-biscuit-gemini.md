# Thoughts on SPKI/SDSI vs Biscuit for the Stroopwafel Project

After reading the `spki-sdsi-vs-biscuit.md` document, the comparison between SPKI/SDSI's distributed, certificate-chaining model and Biscuit's centralized, Datalog-driven model offers fertile ground for a Clojure-native implementation like Stroopwafel.

Given Stroopwafel's goals to leverage `canonical-edn` and `cljc`, blending these two paradigms makes a lot of architectural and functional sense. 

Here are my observations and thoughts on how SPKI/SDSI properties could be integrated into Stroopwafel from an architectural and usability perspective.

## 1. Observations on the SPKI/SDSI vs Biscuit Dichotomy

The document correctly identifies the fundamental architectural split:
*   **SPKI/SDSI** relies on decentralized, offline chain reduction. Group memberships and name definitions are essentially signed certificates. The prover carries the evidence, and the verifier evaluates the chain.
*   **Biscuit** relies on Datalog expressiveness, but practically leans towards a centralized authorizer for resolving groups and roles. While Third-Party Blocks exist, they are scoped external additions rather than a fundamental naming/group resolution algebra.

The proposed "Three-Layer Model" (Verification -> Storage -> Trust/Datalog) is a brilliant reconciliation. It suggests that signed assertions (from SPKI) can be ingested as raw, inert data into a Datalog engine (from Biscuit), which then uses local rules (Trust Roots) to decide which signers to trust and "activate".

## 2. Why Canonical-EDN and Clojure are the Perfect Fit

SPKI/SDSI's original designs leaned heavily on Canonical S-expressions to ensure stable cryptographic hashing over structured data. **Canonical-EDN (CEDN)** is the modern, more capable equivalent for the Clojure ecosystem.

*   **No Protobuf Impedance Mismatch**: Biscuit relies on a fixed Protobuf schema, mapping everything to specific types. Public keys aren't first-class values you can easily pattern match against in facts. In Stroopwafel, using EDN means a public key is just another unified value `[:assertion "ed25519:abc..." "group:engineering" "ed25519:def..."]`. The Datalog engine can join over keys natively, perfectly matching Kex's philosophy.
*   **Isomorphic cljc**: Because you are using `cljc`, both the client (prover) assembling the capabilities and the server (verifier) checking them can share the exact same EDN serialization, structural hashing, and Datalog evaluation code out-of-the-box.

## 3. Adding SPKI/SDSI Properties to Stroopwafel: Usability

Does adding SPKI/SDSI properties make sense from a usability point of view? **Yes, but with careful UX/DX design.**

### The Pros:
1.  **True Offline Verification**: In a pure Biscuit model, the verifier often needs a live database to know if `user("alice")` is in `group("engineering")`. If Stroopwafel adopts the SDSI model where the token *carries* a signed assertion from the group authority, the verifier can operate 100% offline. This is a massive win for edge computing, local-first apps, or disconnected `cljc` frontend verification.
2.  **Delegated Administration without DB Access**: A team lead can sign an EDN capability adding a user to their team, and just send the EDN file/string to the user. The user includes this in their token going forward. No centralized "admin dashboard" or database writes are necessary.

### The Cons & UX Challenges (And how to solve them):
1.  **The "Prover Burden"**: SPKI requires the user/client to gather and present the correct chain of certificates to the verifier. If a user needs 5 assertions to prove they have access, manually constructing that request is horrible UX.
    *   *Stroopwafel Solution*: Provide excellent `cljc` client libraries. The client can maintain a local "wallet" of signed EDN assertions and run a local mini-Datalog query to auto-assemble the minimal set of assertions needed for a specific request.
2.  **Token Bloat**: Appending chains of group assertions directly to an HTTP header might bloat tokens beyond acceptable size limits.
    *   *Stroopwafel Solution*: Support a hybrid "Push/Pull" model. Keep highly-attenuated, short-lived path rules directly in the token (Biscuit-style). Let broader, longer-lived SDSI-style group assertions be independently "pushed" to the verifier's fast-cache or kept in the wallet.

## 4. The "Stroopwafel Sweet Spot"

Combining both approaches into a canonical-edn base leads to a very powerful architecture:

1.  **Uniform Data Format**: Everything—claims, checks, trust roots—is a CEDN block.
2.  **Attenuation (Biscuit-style)**: Retain Biscuit's excellent offline cryptographic attenuation. A client can take a Stroopwafel token and append a block `[:check [:<= :time target-time]]` without server contact.
3.  **Distributed Naming / Groups (SDSI-style)**: Instead of the authorizer magically knowing who is in what group via a mutable DB, the authorizer's state is populated by ingesting signed EDN messages from distributed authorities. 
4.  **Datalog Trust Rooting**: As the Kex integration notes suggest, use the authorizer's own Datalog engine to authorize changes to its own DB. It boots with only a root key policy, ingests signed EDN assertions as inert facts, and uses Datalog derivations to "activate" them.

## 5. Re-evaluation of the Updated Specification

After reviewing the latest additions to the `spki-sdsi-vs-biscuit.md` document (specifically section 5.7), it is clear that the initial usability concerns and UX challenges have been thoughtfully addressed:

1.  **The Prover Burden Is Solved:** Section `5.7.6. Proof Wallet — Client-Side Evidence Assembly` leverages the exact `cljc` solution we proposed. By placing a local Datalog engine on the client (the "wallet"), the burden of chain assembly is fully abstracted away from the end user.
2.  **Token Bloat Is Mitigated:** Sections `5.7.3. Push vs. Pull` and `5.7.4. Token Size vs. Freshness Trade-off` establish clear boundaries for when assertions should be packaged directly within tokens versus kept on the authorizer side for caching.
3.  **Conflict & Lifecycle Rigor:** The updated doc goes beyond surface-level usability to handle the realities of distributed trust:
    *   `5.7.1. Conflict Semantics` provides robust operational solutions (like "scoped authority domains") for when separate trust roots contradict each other.
    *   `5.7.2. Freshness, Revocation, and Assertion Lifecycle` directly tackles the risk of stale claims. By enforcing time-bounded validity directly in the `[:assertion ...]` tuples, revocation naturally degrades into a "stop re-signing" problem rather than requiring centralized, heavy CRL infrastructure.

## Conclusion

The incorporation of these lifecycle and proof-wallet primitives solidifies the architecture. Adding SPKI/SDSI properties to Stroopwafel is no longer just a "nice addition"—the updated document provides a mature, implementable blueprint. 

By leveraging Canonical-EDN and sharing the Datalog evaluation engine across the client and server via `cljc`, Stroopwafel can deliver a highly capable authorization layer that captures the holy grail: **the decentralized, offline trust proofs of SPKI, the precise capability attenuation of Biscuit, and a developer experience unburdened by manual certificate chaining.**