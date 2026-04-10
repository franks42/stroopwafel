# Generic Assertion Schema: Claude Review

**Reviewer:** Claude Opus 4.6
**Document Reviewed:** `docs/generic-assertion-schema.md`
**Other Reviews Consulted:** Gemini 3.1 Pro, GPT-5.4
**Verdict:** Yes, implement — incrementally, on top of what we already built

---

## Executive Summary

The proposal identifies real problems, proposes the right abstractions,
and — crucially — does not require changing the Datalog engine. The
594-line engine is type-agnostic, arity-agnostic, and semantics-agnostic.
It unifies patterns against values. That's all it does, and that's all
it needs to do.

The assertion schema is a **data vocabulary change**, not an engine
change. The power of the proposal is that it makes mandatory what was
previously optional (temporal validity, provenance, assertion identity)
without adding complexity to the evaluation machinery.

The risk is over-engineering the transition. We are closer to the target
than the proposal implies — the unified signed-envelope refactor
(v0.10.2) already gives us sayer, timestamp, and clean signing on every
block. The gap is smaller than it looks.

---

## What the Proposal Gets Right

### 1. Hidden defaults are real security footguns

This is the strongest argument. Today:

- Forgetting a `:when` guard → eternal token (fails open)
- Forgetting to inject `[:time ...]` → expiry check is dead code
- Revocation is external → evaluator has no visibility
- Sayer is a side-channel → can't join on who said what

These are not theoretical risks. They are the kind of bugs that pass
all tests and fail in production six months later when someone issues
a token without an expiry check and nobody notices.

Making `not-before`/`not-after` mandatory eliminates the "forgot to
add expiry" class of bugs entirely. You can still set a wide window,
but you must consciously choose it.

### 2. The three-layer separation is the right framing

```
Assertions  — data, signed, temporal, delegatable, revocable
Templates   — code, versioned, not delegatable, governed by library
Injected    — context, ephemeral, trusted locally, not portable
```

This separation exists implicitly in the current design but is never
named. Making it explicit has architectural value: it clarifies what
a compromised token issuer can and cannot do (issue malicious
assertions, but not inject malicious derivation logic).

### 3. Revocation as a queryable assertion type

Current revocation is external to Datalog — you check revocation IDs
before or after evaluation. The proposal brings revocation into the
same pipeline as everything else. A revocation is just another fact
that participates in joins.

This is cleaner and eliminates the "forgot to check revocation before
evaluating" failure mode.

### 4. The SPKI mapping is precise

The assertion tuple maps directly to SPKI's 5-tuple. This isn't
surface resemblance — the structural correspondence validates the
design. We're not inventing a new model; we're expressing Ellison's
model as Datalog-native data.

---

## Where I Diverge from the Proposal

### 1. Per-assertion signing is unnecessary and expensive

All three reviewers agree on this. A block of 20 assertions does
not need 20 signatures. The block-level signing already provides
integrity and provenance — the sayer signed the block, the block
contains the assertions, the chain proves ordering.

Per-assertion signing only makes sense when assertions from different
sayers are mixed in a single transport container. That's the
third-party block case, which we already handle.

**Recommendation:** Keep block-level signing. The sayer field in the
envelope identifies who signed the block. All assertions in that
block inherit the sayer. Per-assertion signing is available for
cross-issuer cases but is not the default.

### 2. We're closer than the proposal implies

The proposal reads as if we need to redesign the data model from
scratch. But the v0.10.2 signed-envelope refactor already gives us:

| Proposal field | Already have? | Where it lives |
|---|---|---|
| sayer | Yes | `:signer-key` in envelope |
| ts | Yes | `:request-id` (UUIDv7 timestamp) |
| not-before | No | — needs adding |
| not-after | No | — needs adding (`:expires` exists but is optional) |
| assertion-type | Partially | First element of fact vector (by convention) |
| assertion-id | No | — needs adding |
| statement | Yes | Facts in `:message` |
| signature | Yes | `:signature` on envelope |

We need to add three things: `not-before`, `not-after`, and per-fact
`assertion-id`. The rest is already there.

### 3. The full 7-element assertion tuple is unnecessary at the fact level

The proposal puts all metadata into every fact tuple:

```clojure
[sayer ts not-before not-after assertion-type assertion-id statement]
```

But most of these fields are shared across all facts in a block.
Every fact in the same block has the same sayer, same ts, same
not-before, same not-after. Repeating them per-fact is redundant.

The right design — which both GPT and Gemini converge on — is:

- **Envelope carries shared metadata:** sayer, ts, not-before,
  not-after, signature
- **Facts carry per-fact metadata:** assertion-id, assertion-type,
  statement
- **At evaluation time:** expand into the full logical tuple if
  needed for queries that join on sayer or temporal fields

This is exactly what our signed-envelope block already does, with
the addition of `not-before`/`not-after` on the envelope and
`assertion-id` per fact.

### 4. Origin sets must be preserved alongside sayer

GPT is right: provenance (who said it) and scope (who can see it)
are related but distinct. The `sayer` field tells you attribution.
The origin set tells the engine which facts block N's checks can
see. These serve different purposes and both must survive.

The proposal hints that origin sets might become redundant. They
won't. Block isolation — the core Biscuit attenuation guarantee —
depends on origin-set scoping. A fact's sayer tells you where it
came from; the scope rules tell you who gets to use it.

### 5. Templates should be conventions, not constraints

GPT's concern about template rigidity is well-founded. Templates
for common assertion types (capability, name-binding, revocation,
delegation) should ship with the library. But direct pattern
matching on raw fact tuples must always work.

The Datalog engine's power comes from its ignorance — it doesn't
know what `:capability` means. If templates become the only legal
way to write policies, we lose that generality. Templates are
ergonomic shortcuts, not schema enforcement.

---

## Where I Agree with the Other Reviews

### With Gemini

- **Clock skew parameter:** Yes, the pre-filter should accept
  `clock-skew-ms`. Distributed systems need this. Small addition,
  prevents real operational pain.
- **`:revoke-subject`:** Useful for incident response. Revoking by
  assertion-ID is too narrow, by key is too broad. Subject-level
  revocation fills the gap. Can be added as a new assertion type.
- **Content-hash assertion IDs:** Gemini makes a fair case for
  deduplication. But UUIDv7 is simpler, time-ordered (better for
  debugging), and the dedup case is rare. I'd start with UUIDv7
  and add content-hash as an option if dedup becomes a real need.

### With GPT

- **Hybrid envelope schema:** This is the right physical design,
  and it's essentially what we already have. Shared metadata on the
  envelope, per-assertion data inside, expand at evaluation time.
- **Scope as a first-class security concept:** Absolutely. Not
  negotiable. The attenuation guarantee depends on it.
- **"Every link is a signed assertion" is overstated:** Correct.
  Derived facts are ephemeral runtime results, not signed. The
  audit trail covers source assertions, not derivations.
- **Keep migration support narrow and temporary:** The backward-
  compatibility shim that wraps bare facts with hidden defaults
  defeats the purpose. Use it for transition, then remove it.

---

## The Engine Doesn't Care — And That's the Point

The most important property of the current design, which the
proposal preserves, is that the Datalog engine is completely
agnostic to assertion semantics:

```clojure
;; The engine sees this:
(unify pattern fact)
;; It matches position by position.
;; It binds variables.
;; It doesn't know what :capability means.
;; It doesn't know pk-bytes is a public key.
;; It doesn't know 1743000000000 is a timestamp.
;; It just unifies.
```

The engine is 594 lines of pure pattern matching, unification,
fixpoint iteration, and scope filtering. It has no knowledge of
authorization, capabilities, names, time, or trust. It just
evaluates facts and rules.

This means:

- **The assertion schema can evolve** without touching the engine.
  New assertion types, new metadata fields, new templates — the
  engine doesn't care.
- **Type safety comes from Clojure values**, not from schema
  declarations. Keywords compare as keywords, numbers compare as
  numbers, bytes compare by content. The `:when` guards use the
  same type semantics.
- **The same engine handles all deployment patterns** — simple
  fact whitelists, SPKI capability chains, SDSI group resolution,
  temporal constraints, cross-organization delegation. The
  complexity lives in the facts and rules, never in the engine.

Any schema change that preserves this property is safe. The
assertion schema does. That's why it's implementable.

---

## Concrete Recommendation

### What to build (incremental, on v0.10.2)

**Phase 1: Temporal validity on the envelope**
- Add optional `:not-before` and `:not-after` to the signed
  envelope format (alongside existing optional `:expires`)
- Default `:not-before` to signing time (from UUIDv7 timestamp)
- Require `:not-after` at token issuance (no more eternal tokens)
- Pre-filter in evaluation pipeline: discard temporally invalid
  blocks before facts enter the Datalog store

**Phase 2: Assertion identity**
- Add optional `:assertion-id` (UUIDv7) per fact at issuance
- Enable targeted revocation: `[:revoke-assertion <id>]` as a
  fact type that the pre-filter checks

**Phase 3: Revocation in the pipeline**
- `:revocation` assertion type — collected from all blocks and
  authorizer facts
- Pre-filter checks assertion-IDs against revocation set before
  inserting facts into Datalog store
- Also support `:revoke-key` and `:revoke-subject` for broader
  revocation scopes

**Phase 4: Canonical templates**
- Ship standard templates for `:capability`, `:name-binding`,
  `:delegation`, `:revocation`
- Templates are convenience rules, not constraints — direct fact
  matching always works
- Document the assertion-type vocabulary and positional conventions

### What NOT to build

- Per-assertion signing (block signing is sufficient)
- `trusted-assertion?` as a Datalog built-in (use pre-filter)
- Removal of origin sets (scope isolation is a security property)
- Ephemeral authorizer key for injected state (over-engineering)
- Closed template registry (keep Datalog open and composable)

### What stays unchanged

- The Datalog engine (594 lines)
- The signed-envelope format (v0.10.2)
- The block chain structure
- The scope isolation model (origin sets)
- The evaluation pipeline structure (just add pre-filter steps)

---

## Cross-Review Summary

| Concern | Gemini | GPT | Claude |
|---|---|---|---|
| **Worth doing?** | Strongly yes | Yes, with caveats | Yes, incrementally |
| **Per-assertion signing** | Keep logical, optimize physical | Too expensive as default | Block signing sufficient |
| **Pre-filter vs built-in** | Pre-filter | Pre-filter | Pre-filter |
| **Scope isolation** | Not addressed | Must preserve | Must preserve |
| **Injected state** | Fake-sign with ephemeral key | Keep as separate trust class | Keep as separate trust class |
| **Template rigidity** | Not addressed | Warn against | Conventions, not constraints |
| **Clock skew** | Yes, add parameter | Not addressed | Agree with Gemini |
| **Assertion IDs** | Content hash preferred | Neutral | UUIDv7, add hash option later |
| **Revocation scope** | Add `:revoke-subject` | List multiple targets | Start with ID+key+subject |
| **Migration shim** | Not addressed | Narrow and temporary | Agree with GPT |

All three reviews converge on the same core recommendation:
**adopt the assertion tuple as the logical model, keep compact
block-based signing for transport, preserve scope isolation, and
pre-filter before Datalog evaluation.**

---

*Document status: independent review.*
*Date: April 2026.*
*Reviewer: Claude Opus 4.6 (1M context)*
*Related: `generic-assertion-schema.md`, `generic-assertion-schema-gemini-review.md`,
`generic-assertion-schema-gpt-review.md`*
