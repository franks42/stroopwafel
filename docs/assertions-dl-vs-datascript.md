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

*Document status: conceptual guide.*
*Last updated: April 2026.*
*Related: `docs/datalog-as-authorization-join.md`,
`docs/generic-assertion-schema.md`,
`docs/generic-assertion-schema-claude-review.md`*
