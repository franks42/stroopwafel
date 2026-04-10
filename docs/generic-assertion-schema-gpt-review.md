# Generic Assertion Schema: GPT Review

**Reviewer:** GPT-5.4
**Document Reviewed:** `docs/generic-assertion-schema.md`
**Project State Reviewed:** current Stroopwafel evaluator, authorizer, tests, and architecture docs
**Verdict:** Worthwhile, with important design caveats

---

## Executive Summary

The proposed generic assertion schema is a meaningful improvement over the current Stroopwafel representation.

It would make assertions and queries **more consistent**, and in most real policy authoring scenarios it would make them **less complex** and **more concise**. The main reason is that several properties that are currently split across different layers of the system become explicit data: who asserted something, when it was asserted, when it becomes valid, when it expires, and whether it has been revoked.

That said, the proposal currently overstates how much complexity disappears. Some complexity is removed from policy authoring, but not from the system as a whole. In particular:

- scope isolation still needs machinery equivalent to today's origin tracking
- injected local context is still a different trust class than signed token assertions
- per-assertion signing has real size and verification costs
- "every link is a signed assertion" is not true unless derivations themselves are materialized and signed, which the current engine does not do

So the right conclusion is:

**Yes, the change looks worthwhile.**
But the strongest version of it is:

**Adopt the generic assertion tuple as the logical authorization model, while retaining a compact block-oriented physical representation and preserving explicit scope machinery.**

---

## What the Current Project Actually Does

The current implementation confirms that the proposal is addressing real seams in the design, not hypothetical ones.

### 1. Facts are bare tuples; metadata lives elsewhere

Today, Stroopwafel tokens contain plain `:facts`, `:rules`, and `:checks`, and evaluation extracts those directly into the Datalog engine. See `stroopwafel.core/evaluate` in `src/stroopwafel/core.clj`.

This means the following assertion properties are not first-class facts:

- provenance of ordinary facts
- issuance timestamp
- validity interval
- revocation status

Those concerns are handled elsewhere, or not represented inside the query model at all.

### 2. Expiry is currently encoded as ad hoc checks

The current tests show expiry implemented as a check that depends on an injected `[:time ?t]` fact plus a `:when` guard, for example in `e2e-time-expiry` in `test/stroopwafel/core_test.clj`.

That is functional, but it is also exactly the kind of footgun the proposal identifies:

- token authors must remember to write the expiry check
- evaluators must remember to inject the current time
- expiry is expressed as policy logic instead of object metadata

### 3. Runtime context is injected as unsigned local facts

`stroopwafel.authorize/add-facts` explicitly treats request metadata and current context as unsigned runtime facts in `src/stroopwafel/authorize.clj`.

That is a valid design, but it means the current model already has two data classes:

- signed token content
- unsigned service-local context

The new schema does not eliminate that distinction by itself.

### 4. Revocation is external to evaluation

Current revocation support is block-oriented and external. `stroopwafel.core/revocation-ids` returns SHA-256-derived revocation IDs for blocks in `src/stroopwafel/core.clj`, and tests verify those IDs in `test/stroopwafel/core_test.clj`.

That means revocation exists today as infrastructure around evaluation, not as data participating in Datalog joins.

### 5. Provenance is partially queryable today, but only through special injection

The current evaluator injects `[:block-signed-by idx external-key]` facts for trusted third-party blocks in `stroopwafel.core/evaluate`.

That is useful, but limited. It makes signer attribution available only in specific cases, and only at the block level. It does not make sayer/provenance a uniform property of all assertions.

### 6. Scope isolation is an actual security property, not an implementation detail

The architecture document and Datalog engine make clear that Stroopwafel relies on origin-set scoping to enforce attenuation and block isolation. See `trusted-origins` and `eval-token` in `src/stroopwafel/datalog.clj`, and the design explanation in `context.md`.

This is important because it means `sayer` is not a complete replacement for origin sets. Provenance and scope are related, but they are not the same thing.

---

## Would the Change Make Assertions Less Complex?

### Yes, at the semantic level

The proposal would make individual assertions semantically simpler because every assertion would carry the same mandatory outer structure:

```clojure
[sayer ts not-before not-after assertion-type assertion-id statement]
```

That removes several hidden defaults from the current model.

Today, to understand whether a fact is usable, you may need to inspect:

- which block it came from
- who signed that block
- whether some related check encoded temporal validity
- whether the application separately revoked the containing block
- whether some authorizer context was injected to make the check meaningful

The proposed tuple collapses much of that into one place.

### But no, not at the storage/crypto level

Assertions become structurally heavier. Each assertion carries multiple metadata fields and, in the proposal as written, its own signature.

So the accurate statement is:

- **less semantic complexity for policy authors and auditors**
- **more representational complexity and potentially more crypto work for the runtime**

That trade is probably worthwhile, but it is still a trade.

---

## Would the Change Make Queries Less Complex and More Concise?

### Mostly yes

This is one of the strongest parts of the proposal.

Under the current design, many policies are forced to mix three concerns in one place:

- business authorization logic
- temporal validity logic
- service-injected runtime context

For example, expiry in the current system is authored as a check over `[:time ?t]` with a `:when` guard. That is not business logic; it is assertion validity plumbing.

By moving validity windows and revocation into the assertion model itself, ordinary queries can stay focused on the authorization question:

- who is the subject
- what action is requested
- what resource is in scope
- what delegation or name-binding chain resolves the subject

That is cleaner, shorter, and easier to review.

### The biggest concision win is uniform validity handling

Instead of repeatedly writing things like:

```clojure
{:id    :check-expiry
 :query [[:time ?t]]
 :when  [(< ?t expiry-ms)]}
```

the system can uniformly filter assertions using their own validity interval.

That eliminates repetitive policy boilerplate and removes a common omission risk.

### One caution: closed templates can become rigid

The proposal emphasizes template functions per assertion type. That improves consistency, but it also shifts the model away from the current open-ended Datalog style.

That is good if the aim is governance and predictable interoperability.
It is less good if the aim is maximum flexibility for novel fact schemas.

So queries likely become more concise for common cases, but only if the template vocabulary is carefully designed and not made too restrictive.

---

## Would the Change Make the System More Consistent?

### Yes, substantially

This is the most compelling argument for the proposal.

Right now, the authorization story is split across multiple layers:

- assertions are facts in Datalog
- signer information lives in signatures and origin sets
- time validity lives in ad hoc checks
- revocation lives outside the query engine
- local request context is injected separately

The generic assertion schema makes the first four much more uniform by moving them into one explicit data model.

That gives you a more coherent answer to questions like:

- Who said this?
- When did they say it?
- Is it valid now?
- Has it been revoked?
- What statement does it actually make?

In the current design, some of those answers are in facts, some in signatures, some in authorizer code, and some outside the evaluator entirely.

The proposal is better because it reduces those seams.

---

## What the Proposal Gets Right

### 1. It targets a real security footgun

The current expiry model is opt-in. The tests and examples make this visible: expiry only exists if someone authors a check and injects time. That is easy to forget.

Making validity windows mandatory is a real improvement in safety.

### 2. It makes provenance queryable

Today, the evaluator only injects signer facts in a narrow third-party case. The proposal upgrades provenance into a general property of every assertion.

That is a cleaner model, especially for SPKI/SDSI-style reasoning and delegation analysis.

### 3. It brings revocation into the same reasoning model

Current Stroopwafel exposes revocation IDs, but revocation itself is external. The proposal is stronger because revocation becomes visible and composable in the same evaluation pipeline.

That is a meaningful conceptual simplification.

### 4. It separates data governance from logic governance

The document's distinction between assertions, templates, and injected context is useful. It clarifies which things can be delegated or revoked and which things belong to library design.

That is a strong architectural framing.

---

## Where the Proposal Currently Overreaches

### 1. `sayer` does not replace scope isolation

The document suggests origin sets may become redundant for provenance. That part is plausible.
It does **not** follow that origin sets are redundant for security scoping.

Current Stroopwafel uses origin-set scoping to guarantee attenuation and block isolation. A delegated block being signed by someone does not by itself tell the evaluator which prior assertions it is allowed to see.

Recommendation:

- keep origin sets or an equivalent scope graph
- treat `sayer` as provenance metadata, not as a replacement for evaluation scope

### 2. Per-assertion signing is likely too expensive as written

The current system signs blocks and verifies a chain. The proposal signs every assertion individually.

That improves granularity, but it is expensive in both token size and verification cost.

Recommendation:

- keep the generic assertion tuple as the logical model
- retain block-level signing as the physical transport primitive
- allow one signed block to carry multiple assertions sharing envelope metadata
- unroll that into assertion tuples at evaluation time

This keeps the semantic benefits without paying the full per-assertion crypto cost.

### 3. "Every link is a signed assertion" is not true yet

In the current evaluator, derived facts are ephemeral runtime results. The proposal sometimes talks as if the full reduction chain becomes signed data.

That is only true for source assertions. Derived authorizations remain unsiged unless the system explicitly materializes and signs them, which it does not currently do.

Recommendation:

- narrow the claim to "every source assertion is signed"
- if full signed proof trails are desired, treat that as a separate design extension

### 4. Injected state remains a seam

The proposal correctly notes this, and it matters. Current runtime facts such as request parameters, current time, or account state are trusted because they come from the service, not because they are signed.

Recommendation:

- keep injected local context as a separate class from portable signed assertions
- do not blur that distinction just for schema uniformity
- if a uniform tuple form is desired, mark local assertions explicitly as non-portable and service-scoped

### 5. Template governance could become too closed

The proposal's template layer is good for consistency, but it should not accidentally erase one of Stroopwafel's strengths: open-ended Datalog composition.

Recommendation:

- ship canonical templates for common assertion types
- still allow direct matching on `statement` tuples where needed
- avoid making the template catalog the only legal way to express policy joins

---

## Overall Judgment Against the User's Questions

### Less complex?

**For policy authors: yes.**
**For the runtime representation: not automatically.**

The proposal reduces conceptual and authoring complexity by making hidden assertion properties explicit. It does not eliminate the need for scope machinery, trust classification, or efficient verification design.

### More concise?

**Yes, in ordinary policies and checks.**

Removing repeated expiry and revocation plumbing should make most real authorization logic shorter and less fragile.

### More consistent?

**Yes, clearly.**

This is the strongest benefit. The proposal unifies data that is currently spread across facts, signatures, origin metadata, and external revocation logic.

### Worthwhile?

**Yes.**

It looks like a worthwhile direction for Stroopwafel, provided it is implemented as a refinement of the current architecture rather than a naive replacement of all current mechanisms.

---

## Recommendations

### 1. Adopt the tuple as the logical model, not necessarily the wire format

Use the 7-field assertion tuple as the canonical semantic model for evaluation and audit.
Keep a compact block-based signed transport format underneath if needed for performance.

### 2. Prefer pre-filtering over a magical built-in predicate

The proposal leaves open whether `trusted-assertion?` should be a built-in predicate or a pre-filter step.

Recommendation:

- prefer pre-filtering for signature verification, temporal validity, and revocation
- feed only valid assertions into the Datalog engine
- keep Datalog focused on joins and derivation, not environment-dependent side effects

This fits the current architecture better and is easier to test.

### 3. Preserve explicit scope isolation machinery

Do not remove origin sets, or whatever replaces them, unless the replacement gives the same attenuation guarantees as current `trusted-origins`-based evaluation.

This is not optional bookkeeping. It is a core security property.

### 4. Keep portable assertions distinct from local context

Signed cross-boundary assertions and service-local injected facts should remain distinguishable, even if they share a common outer shape.

That trust boundary matters.

### 5. Reconsider per-assertion signatures as the default

Per-assertion provenance is useful. Per-assertion signatures everywhere are probably too expensive.

A better default is:

- signed blocks carrying structured assertions
- optional per-assertion signatures only where cross-issuer mixing inside one block is required

### 6. Be precise about revocation granularity

The proposal improves revocation by making it data-driven. That is good.
But decide clearly whether revocation targets:

- assertion IDs
- signer keys
- delegated authority classes
- whole transported blocks

This should be explicit in the first implementation, not left half-implicit.

### 7. Keep migration support narrow and temporary

The compatibility shim for legacy bare facts is practical, but it reintroduces the very hidden defaults this proposal is trying to remove.

Recommendation:

- use compatibility loading only as a short migration bridge
- do not let legacy wrapping become the long-term model

---

## Final Recommendation

The proposal is directionally correct and worth pursuing.

It would make Stroopwafel's assertion model more explicit, less error-prone, and easier to reason about. It would also make ordinary authorization queries shorter and more uniform by moving validity and provenance concerns out of ad hoc policy logic.

The main correction is architectural discipline:

- keep the new assertion tuple
- keep explicit scope isolation
- keep local injected context as a separate trust class
- avoid paying unnecessary per-assertion crypto costs unless the use case really needs them

If implemented that way, the generic assertion schema would be a real improvement over the current project state rather than just a different representation.

---

## Improvements and Alternatives

Beyond the core review, there are a few concrete ways to improve the proposal and one alternative formulation that may fit Stroopwafel better.

### 1. Keep the tuple as the logical model, not necessarily the wire format

The proposed tuple is a good *semantic* model:

```clojure
[sayer ts not-before not-after assertion-type assertion-id statement]
```

But repeating all of that metadata on every serialized assertion is expensive.

A better design is:

- block or envelope carries shared metadata such as `sayer`, `ts`, `not-before`, `not-after`, and signature
- contained assertions carry only per-assertion fields such as `assertion-id`, `assertion-type`, and `statement`
- evaluation expands these into full logical assertion tuples before Datalog evaluation

This keeps query ergonomics while avoiding the worst token-size and verification overhead.

### 2. Make time semantics stricter

The three time fields should have clearly distinct semantics:

- `ts`: when the assertion was minted
- `not-before`: when it becomes usable
- `not-after`: when it stops being usable

The implementation should also define clock skew behavior explicitly. Without that, distributed systems will produce intermittent authorization failures around validity boundaries.

### 3. Preserve scope as a first-class security concept

The proposal improves provenance, but provenance is not the same thing as evaluation scope.

Current Stroopwafel's attenuation guarantees depend on explicit scope isolation. That needs to survive the redesign, whether as origin sets, scope tags, or a scope graph.

The schema should therefore treat these as separate concerns:

- `sayer` answers who asserted something
- scope metadata answers which assertions can be seen together during evaluation

### 4. Make trust class explicit

The project already has two distinct classes of assertions:

- portable signed assertions that cross trust boundaries
- service-local injected assertions used for request context and runtime state

The schema should represent that distinction directly, rather than implying one homogeneous fact universe.

Even if both use a similar outer shape, they should remain distinguishable in trust and audit semantics.

### 5. Use a schema registry, not a fully closed template universe

Canonical templates are useful and should ship with the library. But the system should not become so closed that only pre-approved assertion types are practical.

A better approach is:

- ship standard templates for common types such as capability, delegation, name-binding, and revocation
- support an extension registry for additional assertion types
- still allow direct matching on raw statements where advanced use cases need it

That preserves Stroopwafel's current Datalog flexibility while improving consistency for common patterns.

### 6. Expand revocation targets early

The proposal's revocation model is already better than today's external-only revocation, but it should define more than just assertion-id and key revocation.

Useful revocation targets include:

- assertion id
- signer key
- subject
- delegation grant
- transport block or container id

That will matter in operational incidents, where revoking a key is often too broad and revoking one assertion at a time is too narrow.

### Alternative: Hybrid Envelope Schema

The strongest alternative to the proposal as written is a hybrid design that keeps Stroopwafel's current block-oriented transport but upgrades the logical authorization model.

Example transport shape:

```clojure
{:issuer ...
 :issued-at ...
 :not-before ...
 :not-after ...
 :scope ...
 :signature ...
 :assertions [{:id ...
			   :type ...
			   :statement ...}
			  ...]}
```

At evaluation time, each inner assertion expands into the full logical tuple:

```clojure
[issuer issued-at not-before not-after type id statement]
```

This alternative has several advantages:

- the same query simplicity as the proposal
- smaller tokens
- fewer signatures to verify
- a cleaner migration path from the current block model
- continued compatibility with append-only signed chain semantics

### Lower-risk incremental alternative

If a full tuple redesign feels too disruptive, there is also an incremental option: keep current facts, but add standardized meta-facts alongside them.

For example:

```clojure
[:assertion-id fact-123]
[:asserted-by fact-123 root-pk]
[:asserted-at fact-123 1743000000000]
[:valid-from fact-123 1743000000000]
[:valid-until fact-123 1743086400000]
[:statement fact-123 [:capability "ops-team" :restart "/api/service"]]
```

This is less elegant than the generic tuple, but it has practical benefits:

- minimal evaluator disruption
- easier migration
- immediate queryability of provenance and validity metadata
- compatibility with today's fact-oriented engine

The trade-off is that some policies become a bit more join-heavy.

### Recommended direction

If the goal is the best long-term architecture, the strongest option is:

1. use the generic assertion tuple as the internal logical model
2. keep a compact envelope or block-based transport representation
3. preserve explicit scope isolation machinery
4. pre-filter for signature, validity window, and revocation before Datalog
5. keep local injected context as a distinct trust class
6. support canonical templates plus extension points

That captures most of the proposal's strengths while avoiding its biggest implementation risks.