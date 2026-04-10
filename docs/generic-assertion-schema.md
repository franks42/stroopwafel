# Generic Assertion Schema for Capability Authorization

> An assertion is a statement made by someone, at a certain time,
> valid for a certain period. Authorization is the reduction of a
> set of mutually consistent assertions to a single conclusion:
> "self asserts this action is permitted" — or it isn't.

---

## Context and Motivation

This document proposes a schema redesign for
[Stroopwafel](https://github.com/franks42/stroopwafel), a
capability-based authorization token library for Clojure derived
from [Biscuit](https://github.com/eclipse-biscuit/biscuit).

Stroopwafel already implements a Datalog-based policy evaluation
engine with cryptographically signed, append-only block chains.
This document does not propose replacing that engine. It proposes
a schema change that makes the computation more explicit, more
auditable, and harder to misuse — by promoting hidden implicit
properties of every assertion to first-class fields in the data.

The intended audiences are:
- **claude-code** and other LLM-assisted implementation tools —
  this document is intended to be usable as an implementation guide
- **Independent reviewers** (Gemini, GPT, human) — sufficient
  context is provided to evaluate the proposal without prior
  Stroopwafel knowledge

---

## 1. The Problem: Hidden Defaults

In Biscuit and current Stroopwafel, every fact in a token block
carries implicit metadata that is never expressed in the data
itself. These are not optional properties — they exist for every
fact, always, with hidden default values:

| Property | What it means | Current representation | Hidden default |
|---|---|---|---|
| **sayer** | who made this assertion | block's crypto signature + origin set | "whoever signed this block" |
| **ts** | when it was asserted | absent — must be injected by authorizer | unknown |
| **not-before** | earliest valid time | `:when` guard written per-check, easy to omit | the dawn of time |
| **not-after** | expiry time | `:when` guard written per-check, easy to omit | forever |
| **revoked?** | has this been revoked | checked externally, outside Datalog | no (unless externally verified) |

This scattering has real consequences:

- **Expiry is opt-in.** A token author who forgets a `:when` guard
  issues a token that never expires. The engine does not warn them.
- **Sayer is not queryable.** You cannot write a Datalog rule that
  joins on who made an assertion, because that information is not
  a fact in the store — it's a side-channel in the origin set.
- **Revocation is external.** The Datalog evaluator has no
  visibility into whether a fact has been revoked. This is
  checked before or after evaluation, not as part of it.
- **Temporal constraints require injected state.** To check
  expiry you must: (a) mint a token with `:when [(< ?t expiry)]`,
  (b) remember to inject `[:time (System/currentTimeMillis)]`
  as an authorizer fact at evaluation time, (c) hope the token
  author and the service operator both got it right.

The new schema makes all of these properties mandatory, first-class,
and part of the data — not the infrastructure.

---

## 2. The Generic Assertion Tuple

Every assertion, regardless of type, has the same outer wrapper:

```
[sayer ts not-before not-after assertion-type assertion-id statement]
```

| Field | Type | Description |
|---|---|---|
| `sayer` | public key bytes, name string, or KERI identifier | who makes this assertion |
| `ts` | unix epoch ms (long) | when the assertion was made |
| `not-before` | unix epoch ms (long) | earliest moment the assertion is valid |
| `not-after` | unix epoch ms (long) | expiry — assertion is invalid at or after this time |
| `assertion-type` | keyword | discriminator: `:name-binding`, `:capability`, `:revocation`, etc. |
| `assertion-id` | UUID or content hash | stable identifier for this assertion (enables revocation by ID) |
| `statement` | tuple `[assertion-type param1 param2 ...]` | the actual content, positional by convention per type |

### Example assertions in EDN

```clojure
;; Name binding: alice-pk is a member of "ops-team"
[alice-pk-bytes 1743000000000 1743000000000 1743086400000
 :name-binding  #uuid "a1b2-..." [:name-binding alice-pk-bytes "ops-team"]]

;; Capability: ops-team may :restart "/api/service"
[root-pk-bytes  1743000000000 1743000000000 1743086400000
 :capability    #uuid "b2c3-..." [:capability "ops-team" :restart "/api/service"]]

;; Revocation: assertion b2c3 is revoked
[root-pk-bytes  1743010000000 1743010000000 9999999999999
 :revocation    #uuid "c3d4-..." [:revoke-assertion #uuid "b2c3-..."]]
```

### Signing

Each assertion tuple is signed by `sayer`'s private key using
Ed25519 over the CEDN canonical bytes of the tuple. The signature
travels alongside the assertion. Verification is: deserialize →
canonicalize → verify signature against `sayer` public key.

This is identical to Stroopwafel's existing block signing — the
scope just changes from "a block of facts" to "a single assertion".

---

## 3. Assertion Types and Statement Schemas

The `statement` field is a tuple whose positional schema is defined
by convention for each `assertion-type`. The evaluator does not need
to understand the semantics of any specific type — it only needs to
unify over tuple positions during joins. The conventions are:

### 3.1 `:name-binding`

Binds a key (or name) to a name. Used for group membership,
role assignment, and SDSI-style name→key resolution.

```clojure
[:name-binding <subject> <name>]
;; subject: public key bytes or existing name string
;; name:    string identifier

;; Examples
[:name-binding alice-pk-bytes "ops-team"]
[:name-binding "ops-team"     "engineering"]   ; group hierarchy
[:name-binding bob-pk-bytes   "alice"]         ; key→name
```

### 3.2 `:capability`

Grants a subject the right to perform an action on a resource,
with optional constraints.

```clojure
[:capability <subject> <action> <resource>]
[:capability <subject> <action> <resource> <constraints-map>]
;; subject:     name string or public key bytes
;; action:      keyword (:read, :write, :restart, :trade, ...)
;; resource:    string path, identifier, or pattern
;; constraints: optional map of additional bounds

;; Examples
[:capability "ops-team"    :restart "/api/service"]
[:capability "alice"       :read    "/api/data"]
[:capability agent-pk-bytes :trade  "AAPL"
             {:max-qty 100 :order-types #{:limit} :not-after 1743086400000}]
```

### 3.3 `:revocation`

Revokes a key, an assertion by ID, or a bloom filter epoch.

```clojure
[:revoke-assertion <assertion-id>]
[:revoke-key       <public-key-bytes>]
[:revoke-bloom     <bloom-bytes> <seq-no>]

;; Examples
[:revoke-assertion #uuid "b2c3-..."]
[:revoke-key       compromised-pk-bytes]
```

### 3.4 `:delegation`

Grants another key the authority to issue assertions of a given
type on behalf of the sayer, within the sayer's own validity bounds.

```clojure
[:delegation <delegate-key> <assertion-type> <scope>]
;; scope: :all or a resource/action pattern

;; Example: root grants ops-lead the right to issue :capability
;; assertions scoped to "/api/service"
[:delegation ops-lead-pk-bytes :capability "/api/service"]
```

---

## 4. Comparison with Biscuit / Current Stroopwafel

### 4.1 Schema comparison

| Concern | Biscuit / Stroopwafel | Generic Assertion Schema |
|---|---|---|
| **Facts** | bare vectors in block `:facts` | assertion tuples with mandatory wrapper |
| **Sayer** | implicit — block signature + origin set | explicit first-class field |
| **Timestamp** | absent | explicit first-class field |
| **Validity window** | opt-in `:when` guards per check | mandatory `not-before`/`not-after` fields |
| **Revocation** | external to Datalog engine | assertable, queryable, participates in joins |
| **Rules** | user-defined Datalog rules, open vocabulary | per-type template functions, closed vocabulary + open composition |
| **Checks** | block-local mandatory queries | expressed as queries over assertions |
| **Policies** | authorizer-only, ordered first-match | expressed as queries over assertions |
| **Origin tracking** | infrastructure side-channel (origin sets) | first-class `sayer` field in data |
| **Audit trail** | derived facts are ephemeral, not stored | every link in the reduction chain is a signed assertion |

### 4.2 Evaluation comparison

**Current Stroopwafel evaluation pipeline:**
```
1. Build fact store (insert block facts with origin sets)
2. Inject authorizer facts (with :authorizer origin)
3. Fire rules to fixpoint (scoped by trusted-origins per block)
4. Evaluate checks per block (fail fast on first failure)
5. Evaluate authorizer policies (ordered first-match, closed-world)
→ {:valid? true/false}
```

**Generic assertion schema evaluation pipeline:**
```
1. Collect all assertions from all sources (token blocks, authorizer, store)
2. Filter: discard temporally invalid (not-before/not-after vs current time)
3. Filter: discard revoked (by checking :revocation assertions)
4. Filter: verify signatures (sayer field matches signing key)
5. Apply query (composed from assertion-type templates) — Datalog joins
6. If query derives a covering capability assertion → allow
   Otherwise → deny
→ {:valid? true/false}
```

Steps 2–4 are now expressed over the same data as step 5, using
the same query language. They are not separate infrastructure.

### 4.3 What is preserved

- **The Datalog engine** — unchanged. Facts, rules, unification,
  fixpoint evaluation are all preserved.
- **Block chain signing** — Ed25519 append-only chain is preserved.
  Assertions within blocks are individually signed; block-level
  signing provides the append-only chain integrity guarantee.
- **Attenuation** — preserved. A delegated block can only add
  assertions with equal or narrower validity windows, signed by
  a key that has been granted delegation authority.
- **Scope isolation** — preserved. Block N rules and checks still
  only see authority + their own + authorizer assertions.
- **Third-party blocks** — preserved. An IdP signs assertions
  (e.g. `:name-binding`) that the token holder appends and the
  authorizer trusts via `:trusted-external-keys`.

### 4.4 What changes

- Facts are no longer bare vectors — they are assertion tuples.
- Origin sets become redundant for provenance (sayer field covers
  it) but may be retained for scope isolation machinery.
- Expiry guards no longer need to be written per-check — temporal
  validity is enforced uniformly in step 2 of evaluation.
- Revocation participates in the same query pipeline rather than
  being an external pre-check.

---

## 5. Assertion-Type Template Functions

Each assertion type has a canonical template — a parameterized rule
fragment that encodes the positional convention of its statement
tuple and exposes clean named variables to query authors.

Templates are the governance unit: adding a new assertion type means
publishing a new canonical template. The evaluator stays generic.

### Template: `name-binding`

```clojure
;; Template rule
{:id   :tmpl/name-binding
 :head [:name-binding ?subject ?name]
 :body [[(trusted-assertion? ?sayer ?ts ?nb ?na :name-binding ?id
                             [:name-binding ?subject ?name])]]}

;; Expands to: given a valid, non-revoked, trusted-sayer assertion
;; of type :name-binding, expose (subject, name) for joining.
```

### Template: `capability`

```clojure
{:id   :tmpl/capability
 :head [:capability ?subject ?action ?resource]
 :body [[(trusted-assertion? ?sayer ?ts ?nb ?na :capability ?id
                             [:capability ?subject ?action ?resource])]]}

;; With optional constraints:
{:id   :tmpl/capability-constrained
 :head [:capability ?subject ?action ?resource ?constraints]
 :body [[(trusted-assertion? ?sayer ?ts ?nb ?na :capability ?id
                             [:capability ?subject ?action ?resource ?constraints])]]}
```

### Template: `revocation`

```clojure
{:id   :tmpl/revoked-assertion
 :head [:revoked-assertion ?target-id]
 :body [[(trusted-assertion? ?sayer ?ts ?nb ?na :revocation ?id
                             [:revoke-assertion ?target-id])]]}
```

Where `trusted-assertion?` is a built-in predicate that handles:
- signature verification (sayer signed the tuple)
- temporal validity (current time within not-before/not-after)
- non-revocation (no matching `:revoked-assertion` for this id)
- trust root check (sayer is trusted or delegation chain is valid)

### Composing templates into a query

```clojure
;; Query: is agent-key allowed to :restart "/api/service"?

;; Step 1: resolve agent-key to a name
{:id   :resolve-subject
 :head [:subject-name ?key ?name]
 :body [[:name-binding ?key ?name]]}

;; Step 2: check capability for that name
{:id   :authorized
 :head [:authorized ?key ?action ?resource]
 :body [[:subject-name ?key ?name]
        [:capability ?name ?action ?resource]]}

;; Policy
{:kind  :allow
 :query [[:authorized agent-key-bytes :restart "/api/service"]]}
```

No assertion-type-specific logic in the query — the templates
handle that. The query author only joins on named variables.

---

## 6. Worked Examples

### 6.1 Simple capability check

**Scenario:** root issues a token granting alice read access to
`/api/data`, valid for 24 hours.

**Assertions:**
```clojure
[root-pk 1743000000000 1743000000000 1743086400000
 :capability #uuid "cap-1"
 [:capability "alice" :read "/api/data"]]
```

**Query:**
```clojure
; templates: capability
; policy
{:kind :allow :query [[:capability "alice" :read "/api/data"]]}
```

**Evaluation:**
1. Assert temporally valid? yes (within 24h window)
2. Assert not revoked? yes
3. Assert sayer trusted? yes (root-pk is trust root)
4. Template derives: `[:capability "alice" :read "/api/data"]`
5. Policy matches → allow

---

### 6.2 Group membership via name-binding

**Scenario:** ops-team has :restart capability. alice is a member
of ops-team. alice presents the token.

**Assertions:**
```clojure
[root-pk ... :name-binding #uuid "nb-1"
 [:name-binding alice-pk "ops-team"]]

[root-pk ... :capability #uuid "cap-1"
 [:capability "ops-team" :restart "/api/service"]]
```

**Query:**
```clojure
; templates: name-binding, capability
{:id :resolve :head [:subject-name ?k ?n] :body [[:name-binding ?k ?n]]}
{:id :authz   :head [:authorized ?k ?a ?r]
               :body [[:subject-name ?k ?n] [:capability ?n ?a ?r]]}

{:kind :allow :query [[:authorized alice-pk :restart "/api/service"]]}
```

**Reduction chain (the audit trail):**
```
name-binding(alice-pk → "ops-team")     [signed by root-pk, valid]
  + capability("ops-team" → :restart "/api/service")  [signed by root-pk, valid]
  → authorized(alice-pk, :restart, "/api/service")
  → self asserts: allow
```

Every link is a signed, auditable assertion.

---

### 6.3 Temporal constraint with external state

**Scenario:** agent may :trade "AAPL" but only if daily loss < $500.

**Assertions:**
```clojure
[root-pk ... :capability #uuid "cap-trade"
 [:capability agent-pk :trade "AAPL" {:max-loss -500.0}]]
```

**At evaluation time, authorizer injects current state as an
assertion** (authorizer-origin, no signature required):
```clojure
[:account-state :daily-pnl -125.50]   ; injected fact, not a signed assertion
```

**Query:**
```clojure
{:id   :trade-within-limits
 :head [:trade-allowed ?key ?sym]
 :body [[:capability ?key :trade ?sym ?constraints]
        [:account-state :daily-pnl ?pnl]]
 :when [(> ?pnl (get ?constraints :max-loss -500.0))]}

{:kind :allow :query [[:trade-allowed agent-pk "AAPL"]]}
```

Note: injected authorizer state does not need to be a signed
assertion — it comes from the trusted service itself. The
distinction is: signed assertions travel in tokens and cross
trust boundaries; injected facts are local service state.

---

### 6.4 Revocation in the query pipeline

**Scenario:** capability cap-trade is revoked after issuance.

**New assertion added by root:**
```clojure
[root-pk 1743050000000 1743050000000 9999999999999
 :revocation #uuid "rev-1"
 [:revoke-assertion #uuid "cap-trade"]]
```

**Evaluation:**
1. Collect all assertions including revocation
2. Template `trusted-assertion?` checks: is `#uuid "cap-trade"` in
   the set of revoked assertion IDs? → yes
3. `:capability` template produces no bindings for cap-trade
4. `:trade-allowed` derives nothing
5. Policy finds no match → deny

Revocation participates in the same pipeline as everything else.
No external pre-check needed.

---

### 6.5 Delegation chain

**Scenario:** root delegates capability-issuance for `/api/service`
to ops-lead. ops-lead grants bob :restart capability.

**Assertions:**
```clojure
;; Root delegates to ops-lead
[root-pk ... :delegation #uuid "del-1"
 [:delegation ops-lead-pk :capability "/api/service"]]

;; ops-lead issues capability for bob (valid only within root's window)
[ops-lead-pk ... :capability #uuid "cap-bob"
 [:capability "bob" :restart "/api/service"]]
```

**Query:**
```clojure
;; Template: delegation-trusted-capability
;; A capability assertion from a non-root sayer is trusted only if
;; that sayer has a valid :delegation assertion from a trusted root.
{:id   :delegated-capability
 :head [:capability ?subj ?action ?resource]
 :body [[:delegation ?delegate-key :capability ?resource-scope]
        [(string-prefix? ?resource ?resource-scope)]
        [:raw-capability ?subj ?action ?resource ?delegate-key]]}
```

The delegation template enforces that ops-lead can only issue
capability assertions scoped to `/api/service` — nothing broader.
This is attenuation expressed as data, not crypto.

---

## 7. Pros and Cons

### Pros

**Provenance is mandatory, not optional.**
Every assertion carries its sayer. You cannot insert a fact
without attributing it. In current Stroopwafel, authorizer-injected
facts have no sayer — they're trusted implicitly.

**Temporality is mandatory, not opt-in.**
`not-before`/`not-after` are required fields. A token author cannot
accidentally issue an eternal assertion — they must explicitly set
the validity window. The evaluator enforces it uniformly, not
per-check.

**Revocation participates in the query pipeline.**
Revocation is just another assertion type. It is expressed,
stored, and queried the same way as everything else. No external
pre-check, no bloom filter infrastructure at a different layer.

**Full audit trail.**
Every step in the reduction from assertions to decision involves
signed data. "Why was this allowed?" can be answered by showing
the chain of assertions that led to the conclusion — all of them
signed, all of them with timestamps and validity windows.

**Query language is unchanged.**
The Datalog engine is unchanged. Template functions are just rules.
Query composition is just rule composition. No new language to learn.

**Assertion-type vocabulary is governed and extensible.**
Adding a new type means publishing a new template. The evaluator
stays generic. Schema governance happens at the template layer.

**Simpler evaluator.**
Temporal validity, revocation, and sayer trust are expressed as
data that the generic Datalog engine evaluates. The evaluator
infrastructure loses its side-channel responsibilities (origin
sets for provenance, external revocation checks, per-check expiry
injection). It just evaluates facts and rules.

### Cons

**Each assertion is larger.**
The wrapper adds 6 fields to every fact. For tokens with many
fine-grained facts, this increases token size. Mitigation: most
real tokens have few assertions (< 20). CEDN canonicalization
keeps serialization deterministic and compact.

**`trusted-assertion?` is a built-in predicate with side effects.**
The temporal/revocation/signature check cannot be a pure Datalog
rule — it needs access to the current time and the revocation set.
This is a built-in predicate that the engine must provide, similar
to how current Stroopwafel injects `[:time ...]` as an authorizer
fact. This is a modest complexity addition to the engine.
Alternative: pre-filter assertions before handing the store to
the Datalog engine (keeps the engine pure, moves filtering to
evaluation pipeline step 2–4 as described in section 4.2).

**Injected authorizer state is a seam.**
Signed assertions and injected authorizer facts (e.g. current P&L)
are different things. The distinction must be clear and enforced
— a confused service could inject facts that override signed
assertions. The current Stroopwafel scope isolation model already
handles this via origin sets; the new schema needs an equivalent
mechanism for injected facts.

**Migration from current Stroopwafel.**
Existing tokens with bare facts in blocks are not directly
compatible. A migration layer could wrap bare facts in assertion
tuples with implicit defaults, but this partially defeats the
purpose (hidden defaults return). Clean break is safer.

---

## 8. Three Governed Layers

A key architectural consequence of this schema is that it makes
explicit a separation of concerns that exists implicitly in
Biscuit/Stroopwafel but is never named:

**Assertions are data** — signed, temporal, auditable, carried in
tokens or stores. Things you can assert, delegate, and revoke.
Controlled by token issuers and delegated authorities.

**Rules/templates are code** — derivation logic that operates on
assertions. They live in the evaluator and the template library,
not in the data. Cannot be signed, delegated, or revoked — they
are governed by schema design and library versioning.

**Injected state is context** — ephemeral service-local facts that
the service operator provides at evaluation time: current time,
account balances, request parameters. Not signed, not auditable
across trust boundaries, but trusted because they come from the
service itself.

```
┌─────────────────────────────────────────────────────┐
│  Token issuers / delegated authorities              │
│  control: ASSERTIONS                                │
│  (capabilities, name-bindings, revocations, ...)    │
│  signed, temporal, auditable, revocable             │
└─────────────────────┬───────────────────────────────┘
                      │ evaluated by
┌─────────────────────▼───────────────────────────────┐
│  Schema designers / library maintainers             │
│  control: RULES / TEMPLATES                         │
│  (derivation logic per assertion type)              │
│  static, versioned, not signable or delegatable     │
└─────────────────────┬───────────────────────────────┘
                      │ enriched by
┌─────────────────────▼───────────────────────────────┐
│  Service operators                                  │
│  control: INJECTED STATE                            │
│  (current time, account state, request context)    │
│  ephemeral, local, implicitly trusted               │
└─────────────────────────────────────────────────────┘
```

This is a stronger separation of concerns than the current
Biscuit/Stroopwafel model, where rules and facts sit together in
the same block with no conceptual distinction between "data someone
asserted" and "logic someone defined."

It also clarifies what **cannot** be delegated or revoked: you
cannot revoke a rule, you cannot delegate the right to change
derivation logic through a token. Those concerns belong to a
different governance layer entirely — library versioning and
schema release management — not to the runtime authorization
system.

This boundary between data and code is also a security property:
a compromised token issuer can issue malicious assertions but
cannot inject malicious derivation logic. The blast radius of
a compromised sayer is bounded to the assertion layer.

---

## 9. Open Questions

1. **Should `trusted-assertion?` be a Datalog built-in predicate or
   a pre-filter step?** Built-in keeps the query self-contained.
   Pre-filter keeps the Datalog engine pure. Which matters more
   for Stroopwafel's use cases?

2. **Should `assertion-id` be a UUIDv7 (time-ordered, from
   Stroopwafel's existing `uuidv7` dependency) or a content hash
   (deterministic, dedup-friendly)?** UUIDv7 is simpler to generate.
   Content hash enables deduplication but requires canonicalization
   before ID assignment.

3. **How does block-level signing interact with per-assertion
   signing?** Each assertion is individually signed by `sayer`.
   The block chain provides append-only integrity for the sequence.
   These are complementary — per-assertion signing proves origin,
   block-chain signing proves order and non-tampering. Both should
   be retained.

4. **What is the assertion schema for authorizer-injected state?**
   Current P&L, buying power, current time — these are not signed
   assertions, they're ephemeral service-local facts. Should they
   use the assertion tuple format with a special `:injected` sayer,
   or remain bare Datalog facts as today?

5. **Attenuation validity bounds.** The proposal states that
   delegated assertions can only narrow validity windows. This
   needs to be enforced — either by the evaluator (compare
   `not-after` of capability against `not-after` of any
   delegation assertion in the chain) or by the signing ceremony
   (refuse to sign assertions that exceed the sayer's own bounds).

---

## 10. Relation to SPKI/SDSI

The generic assertion schema is a direct expression of the
[SPKI/SDSI](https://datatracker.ietf.org/doc/html/rfc2693) model
(Ellison et al., 1996–1998) in Datalog-native form.

SPKI's 5-tuple `(issuer, subject, delegation, tag, validity)` maps
directly to the assertion wrapper:

| SPKI field | Assertion field |
|---|---|
| issuer | sayer |
| (issue time) | ts |
| validity | not-before / not-after |
| tag (what) | statement |
| subject | statement[1] (by convention) |
| delegation | :delegation assertion type |

Where Stroopwafel extends SPKI: the statement field is a Datalog
tuple, making the authorization decision a join over facts rather
than a certificate chain reduction algorithm. The Datalog engine
provides the join semantics that SPKI's name reduction algorithm
provided — but expressed as data and rules rather than a bespoke
algorithm.

See also: `docs/spki-sdsi-vs-biscuit.md` and
`docs/datalog-as-authorization-join.md` for the full comparison.

---

## 11. Implementation Notes for claude-code

This section provides concrete guidance for implementing the
generic assertion schema in Stroopwafel.

### 10.1 Data representation

```clojure
;; Assertion tuple (the unit of storage and signing)
;; Position:  0        1     2           3          4                5              6
;;          [sayer    ts    not-before  not-after  assertion-type  assertion-id   statement]

;; Clojure map representation for construction/inspection
{:type           :stroopwafel/assertion
 :sayer          <pub-key-bytes>          ; Ed25519 public key bytes
 :ts             <long>                   ; unix epoch ms
 :not-before     <long>                   ; unix epoch ms
 :not-after      <long>                   ; unix epoch ms
 :assertion-type <keyword>                ; :name-binding, :capability, etc.
 :assertion-id   <uuid>                   ; UUIDv7 recommended
 :statement      <vector>                 ; positional by type convention
 :signature      <bytes>}                 ; Ed25519 sig over canonical tuple bytes
```

### 10.2 Signing

```clojure
;; Canonical tuple for signing (positional, not map)
(defn assertion->signable [a]
  [(:sayer a) (:ts a) (:not-before a) (:not-after a)
   (:assertion-type a) (:assertion-id a) (:statement a)])

(defn sign-assertion [assertion private-key]
  (let [canonical (cedn/canonical-bytes (assertion->signable assertion))]
    (assoc assertion :signature (crypto/sign canonical private-key))))

(defn verify-assertion [assertion]
  (let [canonical (cedn/canonical-bytes (assertion->signable assertion))]
    (crypto/verify canonical (:signature assertion) (:sayer assertion))))
```

### 10.3 Pre-filter pipeline (recommended approach for evaluator purity)

```clojure
(defn valid-assertion?
  "Returns true if assertion is temporally valid, signature-verified,
   and not revoked. Called as a pre-filter before Datalog evaluation."
  [assertion current-time revoked-ids trusted-keys]
  (and (<= (:not-before assertion) current-time)
       (> (:not-after assertion) current-time)
       (not (contains? revoked-ids (:assertion-id assertion)))
       (or (contains? trusted-keys (:sayer assertion))
           ;; delegation chain check — see section 10.4
           )
       (verify-assertion assertion)))

(defn filter-assertions [assertions current-time revoked-ids trusted-keys]
  (filter #(valid-assertion? % current-time revoked-ids trusted-keys)
          assertions))
```

### 10.4 Inserting assertions into the fact store

After pre-filtering, each assertion's statement tuple is inserted
into the Datalog fact store as a regular fact, tagged with the
assertion's origin:

```clojure
(defn insert-assertion [store assertion block-idx]
  ;; Insert the full tuple for template-level access
  (datalog/insert-fact store
    [(:sayer assertion) (:ts assertion) (:not-before assertion)
     (:not-after assertion) (:assertion-type assertion)
     (:assertion-id assertion) (:statement assertion)]
    #{block-idx})
  ;; Also insert the statement directly for ergonomic template access
  (datalog/insert-fact store (:statement assertion) #{block-idx}))
```

### 10.5 Built-in template rules (ship with the library)

```clojure
(def assertion-templates
  '[;; Name binding template
    {:id   :tmpl/name-binding
     :head [:name-binding ?subject ?name]
     :body [[:name-binding ?subject ?name]]}

    ;; Capability template (3-arity)
    {:id   :tmpl/capability
     :head [:capability ?subject ?action ?resource]
     :body [[:capability ?subject ?action ?resource]]}

    ;; Capability template (4-arity with constraints)
    {:id   :tmpl/capability-constrained
     :head [:capability ?subject ?action ?resource ?constraints]
     :body [[:capability ?subject ?action ?resource ?constraints]]}

    ;; Revocation template
    {:id   :tmpl/revoked
     :head [:revoked-assertion ?id]
     :body [[:revoke-assertion ?id]]}])
```

Note: templates are simple at the Datalog level because the
pre-filter pipeline (10.3) has already handled temporal validity,
signature verification, and revocation. The statement tuples
inserted into the store (10.4) are already clean.

### 10.6 Migration compatibility

To support existing Stroopwafel tokens with bare facts, a
compatibility shim can wrap bare facts in assertion tuples with
implicit defaults at token load time:

```clojure
(defn bare-fact->assertion [fact block-idx root-pk]
  {:type           :stroopwafel/assertion
   :sayer          root-pk
   :ts             0                        ; unknown
   :not-before     0                        ; dawn of time
   :not-after      Long/MAX_VALUE           ; forever
   :assertion-type :legacy-fact
   :assertion-id   (random-uuid)
   :statement      fact
   :signature      nil})                    ; not verified
```

This makes the hidden defaults explicit — they are visible and
inspectable rather than silently assumed. New tokens should not
use this shim.

---

*Document status: design proposal, pre-implementation.*
*Originated: April 2026.*
*Author: Frank Siebenlist (concept) + Claude Sonnet 4.6 (documentation).*
*Next: independent review by Gemini and GPT; resolution of open questions;*
*prototype implementation in `stroopwafel.assertion` namespace.*
