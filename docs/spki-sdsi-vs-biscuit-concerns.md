# SPKI/SDSI vs Biscuit Design Doc — Review Concerns

Review of `docs/spki-sdsi-vs-biscuit.md` (March 2026).

The three-layer model (verification → storage → trust activation) is the
strongest contribution — a genuine architectural insight. The event-sourcing
analogy, trust root rotation procedure, and mapping to existing Stroopwafel
architecture are well done. The concerns below should be addressed if/when
we move forward with implementation.

---

## Architectural Concerns

### 1. Stateless → Stateful Authorizer (Biggest Gap)

Stroopwafel's `evaluate` is currently pure: pass a token + authorizer config,
get a result. The three-layer model implies a *persistent, accumulating* fact
store — a fundamentally different architecture. The document glosses over this.

Phases 7–8 don't address: Is there an `Authorizer` object? A durable store?
How does `evaluate`'s API evolve? This is the hardest engineering question
and it gets the least attention.

### 2. Revocation Without Negation-as-Failure

The proposed `:kind :reject` approach only blocks the *final policy decision*,
not intermediate derivations. During fixpoint evaluation, the revoked assertion
still produces `[:member "engineering" key-alice]`, which participates in all
rule derivations. Other rules that consume that fact fire normally. The reject
check catches it at the end — but derived facts from the revoked membership
already exist in the store and may have produced further derivations.

This is a real semantic gap, not just an aesthetics issue. The document says
"not elegant" but the problem is deeper than elegance.

### 3. Performance is Unaddressed

The model proposes storing *all* cryptographically valid assertions (including
untrusted ones) and filtering via Datalog rules. At scale, the rule engine
iterates over (or indexes into) potentially massive stores of inert assertions
on every evaluation. Current Stroopwafel rebuilds the fact store per `evaluate`
call — there's no indexing, no persistence. The document needs at least a
sketch of how this scales.

---

## Scope Concerns

### 4. Library → Distributed System

Stroopwafel is currently a ~1200-line library with zero deps beyond Clojure +
CEDN. Phases 7–12 push toward: a persistent assertion store, a revocation
service, bloom filter distribution, a client-side proof wallet with its own
Datalog engine. That's not a library anymore — it's a distributed authorization
infrastructure.

Consider whether a layered architecture (core library stays small, extensions
are separate packages) is the right approach.

### 5. Six More Phases on a Complexity Trajectory

Phases 1–3e each addressed concrete Biscuit gaps. Phases 7–12 could easily
triple the codebase for capabilities that are *proposed designs* without known
users yet. Need a "Phase 7 alone delivers X value even without 8–12" argument
— what's the minimum viable extension?

---

## Technical Issues

### 6. Mixed Syntax Throughout

Several examples use Biscuit Datalog syntax (`$variable`, `<-`,
`trusting ed25519/...`) rather than Stroopwafel's native EDN syntax
(`:when`/`:let`, `?variable`, vectors). Sections 5.3, 5.5, 5.6 all have this.
For a Stroopwafel design doc, all examples should be in Stroopwafel's notation.

### 7. Assertion Scope vs. Authority Scope

Trust-activated assertions become authorizer-side facts with `#{:authorizer}`
origin — visible to authorizer rules/policies but invisible to first-party
block checks. Authority block facts have `#{0}` origin and are visible
everywhere. So ingested assertions are strictly *less powerful* than authority
facts.

Is this intentional? Should some trusted assertions be promotable to
authority-equivalent scope? The document doesn't discuss this.

### 8. "No Prior Art" Claim (Section 5.9) is Slightly Overstated

Not mentioned: Keycloak (admin APIs use the same auth engine for
self-management), Oso/Polar (some self-referential policy capability),
GitOps-style signed policy distribution (signed commits as policy assertions).
The specific combination may be novel, but the framing could be more nuanced.

---

## Missing Sections

### 9. Threat Model

For a security-critical system, there should be an explicit threat model.
What's the blast radius of a compromised trust root key? A compromised genesis
state? A malicious assertion that passes signature verification? The revocation
section partially covers recovery, but not systematically.

### 10. Comparison Balance

The document leans toward framing SDSI's properties (offline, distributed,
attributed) as clearly desirable and Biscuit's centralization as limited.
But centralized authorization has real strengths: consistent global state,
simpler debugging, easier auditing of *current* state (not just historical
provenance). The tradeoff discussion could be more balanced.

---

## Structural Suggestions

- Section 5 is very long (5.1–5.9 with deep subsections). The considerations
  (5.7) interrupt the flow between the model (5.1–5.6) and Stroopwafel
  implications (6.x). Consider moving 5.7 to an appendix or separate doc.

- Section 5.7.2 recommended defaults table is useful but belongs closer to
  Phase 7–12 implementation planning than to the conceptual model.

- Consider splitting: keep the comparison + three-layer model as a design
  document, and write a separate implementation proposal that confronts
  the stateful-authorizer question head-on.

---

## Bottom Line

The three-layer model is a real architectural insight worth pursuing. The
biggest risk is that the document tries to be both a conceptual comparison
paper *and* an implementation roadmap, and the roadmap (Phases 7–12)
underestimates the architectural distance from current Stroopwafel to a
stateful authorizer with persistent assertion stores.
