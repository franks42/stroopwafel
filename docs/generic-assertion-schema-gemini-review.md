# Generic Assertion Schema: Gemini Review

**Reviewer:** Gemini 3.1 Pro (Preview)
**Document Reviewed:** `generic-assertion-schema.md`
**Verdict:** Strongly Recommended

---

## Executive Summary

The `generic-assertion-schema.md` proposal represents a significant and worthwhile architectural shift for Stroopwafel. While it trades a degree of data compactness for a more rigid tuple structure, it yields a massive improvement in security, consistency, and query ergonomics. By promoting implicit metadata (temporality, origin, revocation) into explicit, first-class fields, the system becomes "secure by default" and closes several critical security footguns inherent in the original Biscuit-style design.

## 1. Complexity Trade-offs (Data vs. Logic)

*   **Assertions become more complex (Fatter Data):** Instead of a bare vector like `[:capability "alice" :read "/data"]`, every piece of data is now wrapped in a rigid 7-tuple that requires cryptographic signing. Token sizes will inevitably increase.
*   **Queries and evaluation become significantly simpler:** In the current architecture, expiration is handled by writing brittle, manual Datalog checks (e.g., matching a `[:time ?t]` fact and adding a `:when` clause). Revocation is handled entirely outside the Datalog engine. The new schema offloads temporality, trust, and revocation to a generic, system-level pre-filter (`trusted-assertion?`). The downstream policy author can just query for `[:capability ?subject ?action]`, completely ignoring the complex plumbing of *why* that capability is valid.

## 2. Conciseness in Application

*   **Declarative Token Construction:** Token construction becomes much more concise. A token issuer no longer has to manually pair facts with boilerplate `:checks` just to ensure a token expires. By uplifting `not-before` and `not-after` to mandatory properties of the assertion tuple, the token payload becomes purely declarative.
*   **Tighter Policies:** Because the `trusted-assertion?` templates automatically filter out expired or revoked assertions, policy authors don't have to defensively write rules to double-check edge cases. The mental overhead for policy authors is drastically reduced.

## 3. Architectural Consistency

This proposal brings a much-needed unification to the system. Currently, Stroopwafel has fractured models of truth:
*   **Capabilities** live in Datalog facts.
*   **Provenance (the "sayer")** lives in implicit cryptographic block signatures/origin sets.
*   **Temporal rules** live in ad-hoc local checks.
*   **Revocation** lives in a completely external system component before Datalog even spins up.

The new schema **unifies everything**. A revocation is just a fact. A delegation is just a fact. A capability is just a fact. They all participate in the exact same evaluation pipeline. This allows standard Datalog joins to answer robust questions natively, such as: *"Did a trusted IdP explicitly revoke the capability that this specific user is claiming?"*

## Suggestions and Conclusion

**Is the change worthwhile? Yes, highly worthwhile.**

The hidden, implicit defaults of Biscuit-style tokens are a known security risk. If a token minter currently forgets to write a `[:time ?t]` expiration check, they accidentally mint an immortal token, and the system fails open by not warning them. 

By pulling these implicit properties out of the shadows and making them first-class data elements of a mandated schema, the system is made **secure out of the box.** 

Furthermore, creating a clean separation of concerns—where token issuers control *Data* (Assertions) and schema maintainers control *Code* (Templates)—makes the audit trail explicit. You can cryptographically trace every link in a multi-party delegation chain through native Datalog joins. The cost in token payload size is vastly outweighed by the structural integrity, auditability, and safety guarantees this schema provides.

**Recommendations for Implementation:**
1. **Datalog Built-in vs. Pre-filter:** The pre-filter approach (Section 10.3 in the proposal) is highly recommended over a Datalog built-in. It keeps the Datalog engine pure, predictable, and easier to debug, while isolating side-effects (like checking the system clock or revocation lists) to a dedicated pipeline phase before logic evaluation begins.
2. **Assertion IDs:** Favor `UUIDv7` for assertion IDs as proposed. The time-ordering property helps with debugging and visually scanning audit logs, which adds significant value without the overhead of computing content hashes prior to ID assignment.

---

## Substantive Improvements & Refinements

Based on the proposal, here are several substantive improvements that would strengthen the implementation:

### 1. The Performance & Size Elephant: Per-Assertion Signatures
**The Problem:** The proposal states, *"Each assertion tuple is signed by `sayer`'s private key... This is identical to Stroopwafel's existing block signing — the scope just changes from 'a block of facts' to 'a single assertion'."* If a token has 20 facts, this requires generating and verifying 20 Ed25519 signatures (64 bytes each). That adds 1.2KB of signatures to a single token, plus significant CPU overhead for verification, destroying the compactness of Ed25519.
**The Fix:** Keep the 7-tuple as the *logical* data model for the Datalog engine, but optimize the *physical* serialization. Group assertions with the same `sayer`, `ts`, `not-before`, and `not-after` into a single block. Sign the block once. At evaluation time (load time), programmatically "unroll" the block into the discrete 7-tuples for the runtime fact store. You get all the querying benefits of the universal schema with the cryptographic compactness of the original block-chain design.

### 2. Clock Skew and Temporal Evaluation
**The Problem:** The temporal pre-filter `(<= (:not-before assertion) current-time)` is mathematically pure but practically brittle. Distributed systems (Gateways, IdPs, Microservices) always have clock skew. 
**The Fix:** The `valid-assertion?` pre-filter should officially accept a `clock-skew-ms` configuration parameter (defaulting to something like 30-60 seconds). Failing to account for clock skew at the schema level will result in users getting intermittent, unexplainable "Denied" errors during rapid IdP handoffs.

### 3. Unifying "Injected State"
**The Problem:** Section 7 points out that injected state (like current account balance or request parameters) shouldn't be signed, creating a "seam" between assertions and local facts.
**The Fix:** Elevate the authorizer to a first-class `sayer`. Generate an ephemeral "Authorizer Key" in memory at evaluation time. Wrap injected facts in the exact same 7-tuple schema, signed by this Ephemeral Authorizer Key, with a `not-after` of 1 millisecond (or just marking it as ephemeral). This means the Datalog engine *never* has to handle two types of data structures (bare facts vs assertion tuples). The template logic remains 100% pure.

### 4. Content Addressed IDs vs UUIDv7
**The Problem:** Section 9 asks whether `assertion-id` should be a `UUIDv7` or a Content Hash. `UUIDv7` is easy but doesn't prevent replay of the *exact same* capability.
**The Fix:** Despite earlier recommendations, there is a strong case for Content Hashes (e.g., Blake3 or SHA-256 over the canonical bytes of `[sayer ts not-before not-after assertion-type statement]`). If an IdP issues the *exact same* name-binding assertion twice to the same user because of a network retry, UUIDv7 generates two different IDs, bloating the token and the Datalog store. Content hashes naturally deduplicate identical assertions at the data-structure level and allow revocation by hash, which is deterministic.

### 5. Revocation Scope Extensibility
**The Problem:** The proposal includes `:revoke-assertion` and `:revoke-key`. 
**The Fix:** Add `:revoke-subject`. In a real-world SaaS breach, you often don't want to revoke the root key (too broad) or chase down 50 individual assertion IDs (too slow/error-prone). You want to say "Revoke all assertions where `subject == "alice"` immediately."