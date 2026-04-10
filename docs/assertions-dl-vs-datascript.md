# Assertions-DL vs Datascript: Two Datalog Dialects, Two Domains

> Stroopwafel's Datalog is to general Datalog what SQL views are
> to raw SQL — same underlying engine, specialized vocabulary and
> conventions for a specific domain.
>
> If you know Datascript, Datomic, or Datalevin, this document will
> help you map that knowledge to Stroopwafel's authorization dialect.

---

## The One-Sentence Difference

**Datascript is a query language for a database.**
You have data, you ask questions about it, you get result sets.

**Stroopwafel is a decision language for signed assertions.**
You have claims from multiple parties, you evaluate them, you get
allow or deny.

---

## Same Engine, Different Domain

Both are Datalog. Both do:
- Pattern matching via unification
- Variable binding across multiple patterns (joins)
- Rule-based derivation of new facts
- Closed-world assumption (missing = false)

The divergence is in what's built on top:

```
                  Datascript                Stroopwafel
                  ──────────                ───────────
Purpose:          Data retrieval            Authorization decisions
Facts are:        Database records          Signed assertions
Results are:      Tuples (result sets)      Boolean (allow/deny)
Lifetime:         Persistent across txns    Ephemeral per evaluation
Schema:           Declared (attrs, types)   Convention (positions)
Scope:            Flat (all facts visible)  Isolated (per-block origins)
Functions:        Any Clojure               Whitelisted (~35 built-ins)
Size:             ~3000 LoC                 594 LoC
```

---

## Data Model: EAV vs Flat Predicates

### Datascript: Entity-Attribute-Value

Everything is a triple. Entity IDs create the graph:

```clojure
;; Three triples, one entity
[42 :user/name "alice"]
[42 :user/role :admin]
[42 :user/email "alice@example.com"]

;; Query: join on entity ID
(d/q '[:find ?name
        :where
        [?e :user/role :admin]
        [?e :user/name ?name]]
     db)
;; => #{["alice"]}
```

The entity ID `42` is the glue. You navigate the graph by following
entity references. The schema declares what attributes exist, their
types, and their cardinality.

### Stroopwafel: Flat predicate tuples

No entity IDs, no fixed arity. The predicate name (first element)
and positional convention define the structure:

```clojure
;; Flat tuples, variable arity
[:capability "alice" :read "/data"]          ;; 4 elements
[:name-binding alice-pk "ops-team"]          ;; 3 elements
[:trusted-root root-pk :any :any]           ;; 4 elements

;; Query: join on values at positions
{:id   :authorized
 :head [:authorized ?key ?action ?resource]
 :body [[:name-binding ?key ?name]
        [:capability ?name ?action ?resource]]}
```

No entity ID needed — `?name` joins across the two facts directly
by matching the subject of the capability with the name from the
binding. The join is on the value itself, not on an entity reference.

### Can you use EAV in Stroopwafel?

Yes. The engine doesn't care about tuple structure:

```clojure
;; EAV triples work fine in Stroopwafel
[:e/42 :user/name "alice"]
[:e/42 :user/role :admin]

;; Same join-on-entity-ID pattern
{:head [:admin ?name]
 :body [[?e :user/role :admin]
        [?e :user/name ?name]]}
```

And conversely, Stroopwafel's flat predicates could be expressed
as EAV in Datascript — just normalize each predicate into multiple
triples joined on a synthetic entity ID.

The data models are interconvertible. The difference is convention,
not capability.

---

## Schema: Declared vs Positional Convention

### Datascript: Schema is metadata

```clojure
(def schema
  {:user/name  {:db/valueType :db.type/string
                :db/cardinality :db.cardinality/one}
   :user/role  {:db/valueType :db.type/keyword
                :db/cardinality :db.cardinality/one}
   :user/email {:db/valueType :db.type/string
                :db/cardinality :db.cardinality/one}})

(d/create-conn schema)
```

The database enforces types, cardinality, and uniqueness. A wrong
type or duplicate cardinality-one value is an error at transaction
time.

### Stroopwafel: Schema is in the queries

There is no schema declaration. The engine accepts any vector as
a fact. The "schema" emerges from the patterns in rules:

```clojure
;; This pattern IS the schema for :capability facts:
;; "I expect 4 elements: keyword, string, keyword, string"
{:body [[:capability ?subject ?action ?resource]]}
```

If a fact doesn't match — wrong length, wrong type at a position,
misspelled keyword — unification silently produces no result. No
error, no warning. The fact simply doesn't participate.

This is schema-less in the same way that JSON is schema-less: the
structure is there, but it's enforced by the consumer (the query),
not by the producer (the data store).

### Templates formalize the convention

To avoid every rule reimplementing positional knowledge, templates
define the convention once:

```clojure
;; The template IS the schema definition for :capability
{:id   :tmpl/capability
 :head [:can ?subject ?action ?resource]
 :body [[?_ ?_ ?_ ?_ :capability ?_ ?subject ?action ?resource]]}
```

Downstream rules join on the template's derived fact `[:can ...]`
and never touch raw positions. The template absorbs the positional
schema; the policy author works with named predicates.

---

## Query Results: Result Sets vs Decisions

### Datascript: Returns data

```clojure
(d/q '[:find ?name ?email
        :where
        [?e :user/role :admin]
        [?e :user/name ?name]
        [?e :user/email ?email]]
     db)
;; => #{["alice" "alice@example.com"]
;;      ["bob" "bob@example.com"]}
```

The result is a set of tuples. The caller decides what to do with
them.

### Stroopwafel: Returns a decision

```clojure
(sw/evaluate token
  :authorizer
  {:facts    [[:requested-effect :read]
              [:requested-domain "market"]]
   :policies [{:kind :allow
               :query [[:can ?subject :read "market"]]}]})
;; => {:valid? true}   or   {:valid? false}
```

The result is allow or deny. The engine evaluates checks (must all
pass), then policies (first match wins, no match = deny). There is
no "return the matching tuples" — only "is this permitted?"

Rules derive intermediate facts along the way, but those are
ephemeral — they exist only for the duration of the evaluation.
The caller sees the decision, not the intermediate joins.

---

## Fact Lifetime: Persistent vs Ephemeral

### Datascript: Facts persist

```clojure
(d/transact! conn [[:db/add 42 :user/name "alice"]])
;; Fact exists until retracted
(d/transact! conn [[:db/retract 42 :user/name "alice"]])
```

The database is the source of truth. Facts accumulate over
transactions. Datomic adds full history — you can query any
point in time.

### Stroopwafel: Facts are assembled per evaluation

```
1. Collect signed assertions from token blocks
2. Add authorizer-injected context (current time, request params)
3. Evaluate (rules → fixpoint, checks, policies)
4. Return decision
5. Discard everything
```

There is no persistent store. The fact set is built from scratch
for each authorization decision — assembled from multiple sources
(tokens, authorizer, service state), evaluated once, and thrown
away. The token is the durable artifact, not the fact store.

---

## Scope: Flat vs Isolated

### Datascript: One universe

Every query sees every fact. There is no concept of "this fact
came from block 2 and should only be visible to block 2's checks."

### Stroopwafel: Origin-scoped isolation

Facts carry origin tags:

```
Block 0 facts:      origin #{0}         (authority)
Block 1 facts:      origin #{1}         (delegation)
Authorizer facts:   origin #{:authorizer}
Derived facts:      origin = union of inputs + rule source
```

Scope rules determine visibility:

```
Block 0 checks see:    #{0 :authorizer}
Block 1 checks see:    #{0 1 :authorizer}
Authorizer policies:   #{0 :authorizer}
```

This is the attenuation guarantee: a delegated block can add
restrictions (checks that must pass) but cannot access or
override facts from other delegated blocks. Each block sees
the authority's facts plus its own — nothing else.

This has no equivalent in Datascript. It's a security property
specific to the authorization domain.

---

## Functions: Open vs Sandboxed

### Datascript: Any Clojure function

```clojure
(d/q '[:find ?name
        :where
        [?e :user/name ?name]
        [(clojure.string/starts-with? ?name "a")]]
     db)
```

You can call any Clojure function in query predicates. Powerful
but unbounded — there's no restriction on what code executes
during query evaluation.

### Stroopwafel: Whitelisted built-ins only

```clojure
{:body [[:capability ?subject ?action ?resource]]
 :when [(str/starts-with? ?resource "/api/")
        (not= ?action :destroy)]}
```

Expressions in `:when` guards can only use ~35 registered
functions: comparison, arithmetic, string operations, type
predicates, regex. No `eval`, no `resolve`, no namespace lookup,
no I/O.

This is a security boundary. Tokens can carry rules with `:when`
guards, and those rules execute on the evaluator. The whitelist
ensures that a malicious token cannot execute arbitrary code —
only the registered built-in functions.

---

## Fixpoint: One-Pass vs Iterative

### Datascript: Rules evaluate once

Datascript's rules (when used) are applied in a single pass.
Recursive rules require explicit handling.

### Stroopwafel: Rules fire to fixpoint

```clojure
;; Transitive group membership
{:id :transitive-member
 :head [:member-of ?key ?group]
 :body [[:member-of ?key ?mid]
        [:group-contains ?mid ?group]]}
```

Rules fire repeatedly until no new facts are derived (or limits
are reached: 100 iterations, 1000 facts). This handles transitive
delegation chains naturally — a chain of three delegations
resolves in three fixpoint iterations without the query author
writing iterative logic.

---

## The DSL Layers

Stroopwafel's authorization dialect layers domain-specific
conventions on top of the generic Datalog engine:

```
┌─────────────────────────────────────────────────┐
│  Policy author                                   │
│  Writes:  rules over named predicates            │
│           [:can ...] [:named ...] [:authorized]  │
│  Sees:    clean joins, allow/deny result         │
├─────────────────────────────────────────────────┤
│  Template layer (Assertions-DL vocabulary)       │
│  Defines: positional schema per assertion type   │
│           :tmpl/capability, :tmpl/name-binding   │
│  Hides:   raw tuple positions from policy author │
├─────────────────────────────────────────────────┤
│  Pre-filter pipeline                             │
│  Handles: temporal validity, revocation,         │
│           signature verification                 │
│  Ensures: only valid facts enter the engine      │
├─────────────────────────────────────────────────┤
│  Scope isolation                                 │
│  Enforces: block-level origin tracking           │
│            attenuation guarantees                │
│            per-block check visibility            │
├─────────────────────────────────────────────────┤
│  Datalog engine (594 lines, domain-agnostic)     │
│  Does:    unify, bind, eval-body, fire-rule,     │
│           fixpoint iteration, eval-check,        │
│           eval-policy                            │
│  Knows:   nothing about authorization            │
└─────────────────────────────────────────────────┘
```

The bottom layer is generic Datalog — it could evaluate any facts
and rules. The layers above make it an authorization DSL. Strip
the upper layers and you have a bare evaluator. Add them back and
you have Assertions-DL.

This is the same relationship that SQL has with, say, a financial
reporting system: SQL is the generic query language, the reporting
system adds domain tables, views, stored procedures, and access
controls. The engine doesn't change. The domain conventions do.

---

## When to Use Which

| Use case | Datascript/Datomic | Stroopwafel |
|---|---|---|
| Application database | Yes | No |
| Complex data queries | Yes | No |
| Aggregations, analytics | Yes | No |
| Entity graph navigation | Yes | No |
| Authorization decisions | Possible but DIY | Yes (purpose-built) |
| Signed assertions | No | Yes |
| Multi-party trust | No | Yes |
| Scope isolation | No | Yes |
| Embeddable (594 LoC, zero deps) | No | Yes |
| AI agent capability gating | DIY | Yes |
| Cross-boundary token auth | DIY | Yes |

If you need a database, use Datascript. If you need an
authorization decision from signed assertions with scope
isolation, use Stroopwafel. If you need both, use both — they
don't conflict. The authorization decision can even query a
Datascript database for context facts to inject into the
Stroopwafel evaluation.

---

## For Datascript Users: Quick Translation Guide

| Datascript concept | Stroopwafel equivalent |
|---|---|
| `(d/create-conn schema)` | No equivalent — schema-less |
| `(d/transact! conn [...])` | `(datalog/insert-facts store facts origin)` |
| `(d/q '[:find ...] db)` | `(sw/evaluate token :authorizer {...})` |
| `[?e :attr ?v]` pattern | `[:predicate ?arg1 ?arg2]` pattern |
| Entity ID `?e` | No entity model — join on values |
| `:db/valueType` | Convention — Clojure runtime types |
| `:db/cardinality` | No enforcement |
| Pull API | No equivalent |
| Transaction functions | No equivalent |
| `d/history` / `d/as-of` | No equivalent |
| Rules | Rules (same concept, different syntax) |
| — | Checks (must-satisfy constraints) |
| — | Policies (ordered allow/deny, closed-world) |
| — | Origin sets (scope isolation) |
| — | `:when` guards (sandboxed expressions) |
| — | `:let` bindings (computed variables) |

The core Datalog is the same. The vocabulary around it reflects
the domain: databases need transactions, schemas, and indexes;
authorization needs signatures, scope isolation, and decisions.

---

## Lineage: KEX → Stroopwafel → Biscuit

Stroopwafel's engine descends from KEX (a ~470-line Clojure
proof-of-concept by Seref Ayar) and targets feature parity with
Biscuit (the reference implementation in Rust/Java). Here is how
the three engines compare structurally:

### KEX (205 lines) — the starting point

- Single-pass rule firing — rules don't chain transitively
- No scope isolation — all facts visible to all rules and checks
- No expressions — pure pattern matching only, no `:when` guards
- No policies — checks only, check-if semantics only
- No byte-array-aware comparison — uses Clojure's `=` (identity)
- Minimal origin tracking — just `:authority` or `:derived`

### Stroopwafel (594 lines) — what we added

- **Fixpoint iteration** — rules fire repeatedly until no new facts
  (max 100 iterations, 1000 facts). Transitive delegation chains
  resolve naturally.
- **Full scope isolation** — origin sets per fact, per-block
  visibility, trusted-origins filtering. The attenuation guarantee:
  block N sees `#{0 N :authorizer}`, nothing else.
- **Expression guards** — `:when` with ~35 whitelisted functions.
  No eval, no resolve — security-bounded.
- **Computed bindings** — `:let` for intermediate variables.
- **Policies** — ordered allow/deny with closed-world default.
  Separate from checks. First match wins.
- **Reject-if checks** — inverted match semantics for deny rules.
- **Byte-array-aware unification** — `value=` uses
  `java.util.Arrays/equals`. Critical for cryptographic key
  comparison in authorization facts.
- **Trusted third-party scope extension** — authorizer can extend
  visibility to specific third-party block indices.

### Biscuit (3,096 lines, Java) — the reference

- Same fixpoint + scope model as stroopwafel
- **Lazy stream-based evaluation** — `Combinator` implements
  `Iterator<Pair<Origin, Map<Long, Term>>>` for memory-bounded
  left-to-right predicate matching. Handles large fact sets
  without materializing full cross-products.
- **Result monad** error handling (vs our exceptions)
- **Typed term system** — 9 types (integer, string, bytes, date,
  boolean, set, array, map, null) with per-type operations
- **`ALL` check variant** — universal quantification (pass only
  if all candidates match). Stroopwafel has check-if and reject-if
  but not all-must-match.
- **No policies** — checks are the final gate. Stroopwafel added
  the policy layer on top.
- **Protobuf serialization** — binary wire format (vs CEDN)
- **Rule scope decorators** — `Authority`, `Previous`, `PublicKey`
  scope annotations per rule, computed into `TrustedOrigins` at
  runtime

### Divergence summary

| Decision | Stroopwafel | Biscuit | Rationale |
|---|---|---|---|
| Policies | Yes (allow/deny) | No (checks only) | Need a final decision gate |
| Typed terms | No (Clojure values) | Yes (9 types) | Runtime types sufficient, schema-less is simpler |
| Serialization | CEDN | Protobuf | Canonical by design, no base64 |
| Lazy evaluation | No (eager) | Yes (streams) | Fact sets are tiny (<50), lazy overhead not worth it *yet* |
| Universal checks | No | Yes (`ALL`) | Not needed yet — could add |
| Error handling | Exceptions | Result monad | Clojure idiom vs Java idiom |

### What's identical across all three

The core semantics are shared:

- Pattern matching via positional unification
- Facts as flat tuples with a predicate name
- Rules derive new facts from existing ones
- Closed-world assumption (missing = false)
- Variables as `?`-prefixed symbols (KEX/stroopwafel) or
  `$`-prefixed indices (Biscuit)

Stroopwafel is essentially Biscuit's evaluator compressed into
idiomatic Clojure, with policies added and typed terms removed.
The deviation from KEX is substantial — we kept the namespace
and basic `unify`/`fire-rule` structure but rewrote almost
everything else for scope isolation and fixpoint.

---

## TODO: Engine Optimizations

The current engine is correct and fast for small fact sets (<50
facts, typical for per-request authorization). For larger
deployments (central PDP with organizational hierarchies,
WebSocket RPC with hundreds of function permissions), the
following optimizations would reduce memory allocation and
improve throughput:

### 1. Transducers in `facts-for-scope`

Called on every rule firing during every fixpoint iteration.
Currently allocates a lazy seq per call.

```clojure
;; Current: lazy seq (allocates thunks)
(for [[fact origin] store
      :when (visible? origin trusted)]
  [origin fact])

;; Optimized: transducer (no intermediate allocation)
(into []
      (keep (fn [[fact origin]]
              (when (visible? origin trusted)
                [origin fact])))
      store)
```

### 2. Transducers in `apply-rules-scoped`

The fixpoint loop's inner reduce. Each iteration filters facts
per scope, fires rules, and collects new facts. Transducers
would eliminate intermediate seq allocations across the full
iteration.

```clojure
;; In the inner rule-firing loop, replace:
(let [derived (fire-rule rule visible block-idx)]
  (reduce (fn [s2 {:keys [fact origin]}] ...)
          s derived))

;; With a transducing approach that avoids materializing
;; the full derived seq before reducing into the store.
```

### 3. Early termination in `eval-check`

For `:one` checks (pass on first match), stop after the first
successful unification instead of evaluating all candidates:

```clojure
;; Current: evaluates all, takes first
(let [results (filter ... (eval-body query origin-facts))]
  (if (seq results) ...))

;; Optimized: stop at first match
(let [first-match (first (filter ... (eval-body query origin-facts)))]
  (if first-match ...))
```

Note: `eval-body` already returns a lazy seq from `for`, so
`first` would only realize one match. But the intermediate
`filter` and `eval-when` may still realize more than needed.
Wrapping in a `reduce` with `reduced` would guarantee early
exit.

### 4. Leave `eval-body` lazy

The cross-product in `eval-body` (states × facts per pattern)
is already lazy via `for`. This is correct — most candidates
fail unification, and laziness avoids materializing the full
cross-product. Do not convert this to eager/transducer form.

### 5. Consider: indexed fact lookup

For large fact sets (>500 facts), linear scan in `eval-body`
becomes the bottleneck. An index on the first element of each
fact (the predicate name) would turn O(facts) into O(facts
with matching predicate):

```clojure
;; Indexed store: {predicate-keyword → [{fact origin} ...]}
;; Lookup: only scan facts matching the pattern's first element
```

This is what Datascript's EAVT/AEVT indexes do for EAV triples.
For flat predicates, indexing on position 0 (the predicate name)
captures most of the benefit with minimal complexity.

Not needed until fact sets routinely exceed a few hundred entries.

---

*Document status: conceptual guide.*
*Last updated: April 2026.*
*Related: `docs/datalog-as-authorization-join.md`,
`docs/generic-assertion-schema.md`,
`docs/generic-assertion-schema-claude-review.md`*
