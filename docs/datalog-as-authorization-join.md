# Datalog as Authorization Join Across Trust Boundaries

> Authorization is a join. The authority says one thing, the server
> knows another, the request carries a third. The question is: do
> these independent sources of truth agree?
>
> Datalog makes this join explicit, composable, and transport-independent.

---

## Why Datalog?

The authorization decision depends on facts from three independent
parties, each with their own concerns:

```
Authority (token issuer)         "what may this agent do?"
Server (PEP deployer)            "how do wire requests map to functions?"
Client (requester)               "what is being requested right now?"
```

No single party has the full picture. The authority doesn't know the
server's transport. The server doesn't know the authority's policy
intent. The client doesn't know either — it just sends a request.

Datalog's job is to join these three fact sets and produce a yes/no
decision. Each party contributes facts from their own domain:

```
Authority concerns:     [:may-invoke :market/quote]           (what)
Server concerns:        [:route-maps "/market/quote" :market/quote]  (how)
Request concerns:       [:requested "/market/quote"]          (this)
                        ─────────────────────────────────────────
Datalog join:           [:can-call :market/quote]             (yes/no)
```

Nobody needs to understand the full picture. The join IS the decision.

---

## The Three Fact Sets

### 1. Policy facts (in the token — travel with the request)

These express the authority's intent in terms of **function-ids** —
abstract identifiers for operations, independent of any transport
binding:

```clojure
;; Issued by the authority, carried in the token
[:may-invoke :market/quote]
[:may-invoke :market/bars]
[:may-invoke :dashboard/layout]
;; notably absent: :admin/drop-tables
```

The authority thinks in terms of capabilities: what may this agent do?
Not how the request arrives. Not what URL path it uses. Just: which
operations are permitted.

### 2. Transport mapping facts (in the authorizer — provided by the PEP)

These bind wire-level identifiers to function-ids. They are
deployment-specific — the same function-id can be reached via
different transports:

```clojure
;; REST deployment
[:route-maps "/market/quote"  :market/quote]
[:route-maps "/market/bars"   :market/bars]

;; WebSocket RPC deployment
[:route-maps "market/quote"   :market/quote]
[:route-maps "market/bars"    :market/bars]

;; Message-based deployment
[:route-maps :price-request   :market/quote]
[:route-maps :bars-request    :market/bars]
```

The server thinks in terms of its own transport: what wire identifier
maps to what function? This is a deployment concern, not a policy
concern.

### 3. Request facts (in the authorizer — provided at eval time)

These capture what arrived on the wire:

```clojure
;; What the client actually sent
[:requested "/market/quote"]     ;; REST
[:requested "market/quote"]      ;; RPC
[:requested :price-request]      ;; messaging
```

---

## The Join

A single Datalog rule connects all three:

```clojure
{:id   :authorized
 :head [:can-call '?fn]
 :body [[:route-maps '?wire-id '?fn]   ;; server: wire → fn
        [:requested '?wire-id]          ;; client: what was asked
        [:may-invoke '?fn]]}            ;; authority: what's allowed

{:kind :allow
 :query [[:can-call '?fn]]}
```

The join produces a result only when all three agree:
- The wire-id maps to a known function-id (server says: this route exists)
- That wire-id is what was requested (client says: this is what I want)
- That function-id is permitted (authority says: this agent may call it)

If any link is missing, the join produces nothing — request denied.

---

## Separation of Concerns

This architecture cleanly separates three independent decisions:

| Concern | Who decides | Where facts live | Changes when |
|---|---|---|---|
| **Policy** | Authority | Token | Agent's permissions change |
| **Transport mapping** | Server deployer | Authorizer (PEP) | Server transport changes |
| **Request identity** | Client | Authorizer (eval time) | Each request |

This separation has practical consequences:

**The token is transport-independent.** The same token with
`[:may-invoke :market/quote]` works whether the server uses REST,
WebSocket RPC, or carrier pigeons. The authority doesn't need to know
or care about the transport. Redeploying a server from REST to
WebSocket doesn't require reissuing tokens.

**The transport mapping is policy-independent.** Adding a new route
`"/v2/market/quote"` that maps to `:market/quote` doesn't require
policy changes. Existing tokens just work via the new route.

**Unmapped routes are denied by absence.** If a wire-id has no
`[:route-maps ...]` fact, the join produces nothing. No explicit deny
rule needed. The closed-world assumption — if the fact isn't there,
the answer is no — is the core security property.

---

## Why Closed-World Matters

SQL can do joins too. What makes Datalog special for authorization
is the **closed-world assumption**: if a fact is not in the database,
it is false. There is no NULL, no UNKNOWN, no "maybe."

For authorization, this is exactly the right semantics:

- No `[:may-invoke :admin/drop-tables]` in the token → agent cannot
  call it. Period. No rule needed to deny it.
- No `[:route-maps "/secret/backdoor" ...]` in the server → that
  path doesn't exist. Period. No 404 handler needed.
- No `[:requested ...]` fact → nothing was asked. Period.

Every missing fact is an implicit denial. You only need to express
what IS allowed. The absence of permission is the denial. This means
the system is secure by default — you add capabilities, you don't
remove restrictions.

This is the SPKI/SDSI philosophy expressed as a database property:
capabilities are additive. The empty token has zero permissions.
Each fact adds a capability. The join determines which added
capabilities apply to this specific request.

---

## Composing with Richer Policy

The function-id abstraction composes naturally with the effect/domain
model already used in alpaca-clj. The authority can express policy
at multiple levels of granularity in the same token:

```clojure
;; Coarse: effect + domain (as today)
[:may-invoke :market/quote]
[:may-invoke :market/bars]

;; Fine: parameter constraints
[:allowed-symbol "AAPL"]
[:allowed-symbol "MSFT"]

;; Structural: effect classes
[:effect :read]
[:domain "market"]
```

And the Datalog rules combine them:

```clojure
;; Route to function
{:id   :route-resolved
 :head [:resolved-fn '?fn]
 :body [[:route-maps '?wire-id '?fn]
        [:requested '?wire-id]
        [:may-invoke '?fn]]}

;; Parameter constraint (when applicable)
{:id   :symbol-ok
 :head [:param-ok '?sym]
 :body [[:allowed-symbol '?sym]
        [:requested-symbol '?sym]]}

;; Combined policy
{:kind :allow
 :query [[:resolved-fn '?fn]
         [:param-ok '?sym]]}
```

The layers are independent — you can have route mapping without
parameter constraints, or parameter constraints without effect
classes. Each layer adds facts and rules; the join determines
what's permitted.

---

## Implications for Testing

The separation of concerns implies a natural testing strategy with
three independent layers:

### Layer 1: Policy facts (transport-independent)

Test the authority's intent in isolation. No routes, no wire format,
no transport. Just function-ids and the policy decision:

```clojure
;; "Can this token invoke :market/quote?"
(sw/evaluate token
  :authorizer
  {:facts [[:may-invoke-requested :market/quote]]
   :checks [{:id :allowed
             :query [[:may-invoke :market/quote]]}]
   :policies [{:kind :allow
               :query [[:may-invoke :market/quote]]}]})
```

### Layer 2: Transport mapping (deployment-specific)

Test that wire-ids resolve to function-ids correctly. No policy,
no tokens. Just the mapping:

```clojure
;; "Does /market/quote resolve to :market/quote?"
;; "Does /nonexistent resolve to anything?" (should not)
```

### Layer 3: Integration (full join)

Test the complete chain: wire-id → function-id → policy decision.
This is where all three fact sets come together:

```clojure
;; "Request for /market/quote with this token → allowed?"
;; "Request for /admin/drop-tables with this token → denied?"
;; "Request for /nonexistent with this token → denied?"
```

Each layer can be tested independently because the concerns are
separated in the Datalog facts. A policy test doesn't need a server.
A mapping test doesn't need a token. Only the integration test
needs both.

---

## Connection to SPKI 5-Tuple Reduction

Carl Ellison's SPKI certificate theory (RFC 2693) defines an explicit
algebra for collapsing delegation chains. Each certificate in the chain
is a 5-tuple `<Issuer, Subject, Delegation, Authorization, Validity>`.
When two adjacent certificates form a delegation chain, they are
**reduced** into a single 5-tuple by:

- Keeping the outer issuer and inner subject
- **Intersecting** the authorization tags (permissions can only narrow)
- **Intersecting** the validity periods
- Checking that delegation was permitted at each link

This is the SPKI monotonicity property: as the delegation chain grows
longer, the resulting authorization can only shrink or stay the same —
never expand. A delegated certificate cannot grant more than its
delegator possessed.

```
SPKI 5-tuple reduction:

  <Root, A, true, {read,write}, Jan-Dec>
    ⊗
  <A, B, false, {read}, Mar-Jun>
    =
  <Root, B, false, {read}, Mar-Jun>     ← intersection of both
```

Datalog gives us the same reduction semantics, but declaratively.
Instead of defining explicit intersection operators for each component,
the Datalog join does the intersection implicitly:

```
Datalog join (equivalent reduction):

  Token facts:        [:may-invoke :market/quote]        (authority)
  Server facts:       [:route-maps "/market/quote" :market/quote]  (mapping)
  Request facts:      [:requested "/market/quote"]       (this request)
                      ─────────────────────────────────────
  Join result:        [:can-call :market/quote]          (reduced)
```

If any link in the chain is missing — the route doesn't exist, the
function isn't permitted, the request doesn't match — the join produces
nothing. This is the same as a failed authorization intersection in
SPKI: the reduction fails, the chain doesn't resolve, access denied.

The closed-world assumption provides monotonicity for free. You can
only add facts that further constrain the join, never broaden it.
Adding `[:allowed-symbol "AAPL"]` to the token narrows what's
permitted. There is no fact you can add that says "ignore the other
constraints" — the Datalog engine has no negation-as-override, no
`NOT` that could punch holes in the policy.

Ellison had to define the reduction algebra explicitly — the
intersection operators for authorization tags, validity periods,
and delegation bits. With Datalog, the algebra is the join semantics
themselves. The rules declare what must be true simultaneously; the
engine finds the intersection. Same result, different expression.

| SPKI concept | Datalog equivalent |
|---|---|
| 5-tuple | Set of facts |
| Certificate chain | Facts from multiple sources |
| Reduction (⊗) | Join across fact sets |
| Authorization intersection | Closed-world: missing fact = denied |
| Validity intersection | Temporal facts in authorizer |
| Delegation bit | Presence of delegation rule |
| Monotonicity | Closed-world assumption |

### Historical note

Datalog was well-established in database theory by the late 1980s,
but when Ellison designed SPKI's reduction algebra in the mid-1990s,
Datalog had no practical implementations — it was an academic subject.
The explicit 5-tuple reduction operators were a pragmatic choice for
the time.

Similarly, SPKI/SDSI's key-based authorization model — where the
public key IS the identity and capabilities travel with the request —
was developed alongside the X.509 CA hierarchy, which took a
different path: identity as a name blessed by a certificate authority.

Both Datalog and key-based authorization are now finding their natural
domains. Datalog powers authorization in systems like Datomic,
DataScript, and Biscuit. Key-based capability tokens are a natural
fit for AI agents, API authorization, and service-to-service
communication — contexts where the question is "what may this key do?"
rather than "what is this key's human-readable name?"

Stroopwafel combines both: Ed25519 signed block chains (SPKI's
key-is-the-principal model) with Datalog evaluation (declarative
policy joins). The 5-tuple reduction algebra and the Datalog join
express the same idea — authorization narrows along a delegation
chain — but Datalog expresses it as generic, composable facts and
rules rather than bespoke operators.

---

## The Insight

Authorization is not a function. It's a join.

The traditional approach — `(authorized? user action resource)` —
hides the join inside imperative code. The facts are scattered across
configuration files, database tables, middleware chains, and ad-hoc
checks. Changing the policy means changing code.

The Datalog approach makes the join explicit. The facts are data.
The rules are data. The policy is data. The enforcement code is
generic — it just runs `sw/evaluate`. Changing the policy means
changing facts in a token, not code in a deployment.

This is why the same PEP pipeline works for REST proxies, WebSocket
RPC, browser sessions, AI agents, and carrier pigeons. The enforcement
code doesn't know what it's protecting. It just joins facts and checks
if the result is non-empty.

---

## Deployment Spectrum: How Facts Reach the PDP

Once a signed token is verified, the signature disappears. What
remains is just facts in a Datalog database. The authorization
decision is always the same: evaluate facts, run the join, yes or no.

This means the signed capability token is one delivery mechanism
for getting facts into the database — not the only one:

```
Capability tokens:     facts travel WITH the request
Central PDP service:   facts are ALREADY THERE when the request arrives
Hybrid:                some facts travel, some are pre-loaded
```

All three converge to the same place: a Datalog DB with facts from
multiple sources, a query, and a decision. The authorization model
is identical — only the fact delivery mechanism differs.

### When tokens shine

- **PDP co-located with resource** — no network call for authZ,
  the facts arrive with the request
- **Cross-organizational boundaries** — fact source and PDP don't
  share infrastructure, signed tokens carry trust across the gap
- **Offline/disconnected operation** — the request carries its own
  proof, no need to phone home
- **Delegation chains** — intermediate parties can attenuate
  (narrow) the facts without contacting the original authority

### When a central PDP shines

- **Single network** — everything can reach the PDP, no need to
  carry facts around
- **Frequently changing facts** — role changes, revocations,
  dynamic policy updates take effect immediately
- **Single audit point** — every decision logged in one place
- **Simpler deployment** — fewer moving parts, easier to reason about

### The hybrid (what most real systems become)

In practice, systems often combine both:

- **Long-lived facts pre-loaded** at the PDP: role mappings,
  transport bindings, resource registrations, roster membership
- **Short-lived facts delivered per-request** via capability tokens:
  specific grants, time-limited permissions, agent key bindings

The PEP at the resource calls `sw/evaluate` with facts from both
sources — the pre-loaded database and the incoming token. The
Datalog engine doesn't distinguish between them. A fact is a fact
regardless of how it arrived.

### The point

The authorization model does not change between these deployment
choices. Same facts, same rules, same Datalog evaluation, same
`sw/evaluate` call. Choosing between tokens, a central PDP, or a
hybrid is a deployment decision — driven by network topology,
latency requirements, and operational simplicity — not an
architecture change.

Separate the authorization model from the fact delivery mechanism,
and the deployment becomes a configuration choice. Simple is better.

---

*Document status: design rationale.*
*Last updated: March 2026.*
*Related: `docs/websocket-rpc-enforcement.md`,
`docs/dual-pep-client-server-enforcement.md` (in alpaca-clj),
[RFC 2693 — SPKI Certificate Theory](https://www.rfc-editor.org/rfc/rfc2693)*
