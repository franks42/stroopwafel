# WebSocket RPC Enforcement with Stroopwafel

> Any RPC channel is an eval channel. Without policy enforcement,
> the client can execute arbitrary server-side code. Stroopwafel
> turns an open eval channel into a capability-gated RPC endpoint.

---

## The Problem

Browser→server communication over sente-lite, websockets, or any
RPC-like messaging channel is structurally equivalent to an nREPL
connection: the client sends a message saying "execute this function
with these arguments" and the server complies.

```
Browser: {:fn "admin/drop-tables" :args {:confirm true}}
Server:  (admin/drop-tables {:confirm true})    ;; 💥
```

Authentication alone doesn't solve this. The browser is authenticated —
it's a legitimate user session. The question is: **which functions may
this session invoke, and with what arguments?**

This is the same problem as the AI agent scenario: the requester
constructs the intent, but the enforcer must gate the action.

---

## Message-Based Enforcement

Stroopwafel's security model is message-based, not session-based. Every
security property travels with the message. This maps perfectly to
RPC-over-websocket, where each message is an independent request:

```
Browser                                Server
══════                                 ══════

  construct RPC call
  {:fn "market/quote"
   :args {:symbol "AAPL"}}

  client-side PEP checks
  outbound token
  (approved fns, data restrictions)

  sign message with
  browser-side key              ──►    server-side PEP
  (Ed25519 via WebCrypto API)
                                         1. verify signature
                                         2. check token grants
                                            [:invoke "market/quote"]
                                         3. if denied → drop message

                                         if allowed → dispatch fn

                                   ◄──  result message
```

The fn-as-URL pattern from alpaca-clj maps directly: instead of
`POST /market/quote`, it's `{:fn "market/quote"}` over the channel.
The structural whitelist is the same concept — only vetted function
names dispatch, everything else is dropped before reaching application
code.

### Why explicit routes matter

In alpaca-clj, every valid operation is a literal path in the routing
table (`"/market/quote"`, `"/trade/place-order"`). There are no
wildcards, no `/api/:resource/:action` patterns, no catch-all routes.
The router IS the whitelist because the route table is static and
exhaustive — if a path isn't in the table, it's a 404 before any
application code runs.

The same principle applies to websocket RPC. If the dispatcher does
`(resolve (symbol fn-name))` on arbitrary strings, that's the
equivalent of a `/*` catch-all route — everything dispatches, nothing
is gated, and you're back to the open-eval problem. The `[:invoke
"market/quote"]` facts in the token serve as the explicit routing
table for the channel.

The structural whitelist only works when the route/function table is:
- **Static**: defined at deploy time, not constructed from request data
- **Exhaustive**: every valid name is listed, not matched by pattern
- **Literal**: no wildcards, no regex, no dynamic segments

When any of these properties is lost — wildcard routes, dynamic
dispatch, catch-all handlers — the routing layer becomes a pass-through
and can no longer serve as an implicit whitelist. That's when the
explicit policy facts in the token become the *only* whitelist, and the
PEP is load-bearing rather than defense-in-depth.

---

## Simple Case: Flat Invoke Facts

For many applications, the policy is a simple whitelist of callable
functions. The same Datalog engine evaluates it — just with flat facts
and checks, no rules or joins:

```clojure
;; Token issued to the browser session
(sw/issue
  {:facts [[:invoke "market/quote"]
           [:invoke "market/bars"]
           [:invoke "dashboard/layout"]
           [:invoke "dashboard/update-prefs"]
           ;; notably absent: "admin/drop-tables"
           ]}
  {:private-key authority-key})
```

Enforcement is a single check:

```clojure
;; Server-side PEP for each incoming RPC message
(sw/evaluate token
  :authorizer
  {:checks [{:id    :fn-allowed
             :query [[:invoke requested-fn]]}]
   :policies [{:kind :allow
               :query [[:invoke requested-fn]]}]})
```

This is the simplest possible policy. If the function name isn't in
the token's fact set, the message is dropped. The token IS the whitelist.

Crucially, this still runs through `sw/evaluate` — the same Datalog
engine, the same PEP pipeline, the same deployment. The simplicity
is in the facts (flat, no joins), not in a different code path. This
means you can enrich the policy later (add parameter constraints,
role-based rules) without changing the enforcement infrastructure.
The deployment stays generic; only the token contents change.

---

## Richer Case: Parameter-Level Policy with Datalog

When the policy needs to constrain not just *which* functions but
*how* they're called, Datalog earns its keep. The function name alone
isn't enough — the parameter values matter:

### Example: Symbol universe restriction

```clojure
;; Token: this session may only query specific symbols
(sw/issue
  {:facts [[:invoke "market/quote"]
           [:invoke "market/bars"]
           [:allowed-symbol "AAPL"]
           [:allowed-symbol "MSFT"]
           [:allowed-symbol "GOOG"]]}
  {:private-key authority-key})

;; Enforcement: fn allowed AND symbol in approved set
(sw/evaluate token
  :authorizer
  {:facts [[:requested-fn "market/quote"]
           [:requested-symbol (:symbol args)]]
   :rules [{:id   :fn-with-symbol
            :head [:can-invoke '?fn '?sym]
            :body [[:invoke '?fn]
                   [:requested-fn '?fn]
                   [:allowed-symbol '?sym]
                   [:requested-symbol '?sym]]}]
   :policies [{:kind :allow
               :query [[:can-invoke '?fn '?sym]]}]})
```

### Example: Role-based function access

```clojure
;; Token: session has a role, roles map to function groups
(sw/issue
  {:facts [[:role "analyst"]
           [:role-can-invoke "analyst" "market/quote"]
           [:role-can-invoke "analyst" "market/bars"]
           [:role-can-invoke "analyst" "dashboard/layout"]
           [:role-can-invoke "admin" "admin/reset-cache"]
           [:role-can-invoke "admin" "admin/drop-tables"]]}
  {:private-key authority-key})

;; Enforcement: role → function mapping via join
(sw/evaluate token
  :authorizer
  {:facts [[:requested-fn "market/quote"]]
   :rules [{:id   :role-dispatch
            :head [:authorized-fn '?fn]
            :body [[:role '?r]
                   [:role-can-invoke '?r '?fn]
                   [:requested-fn '?fn]]}]
   :policies [{:kind :allow
               :query [[:authorized-fn '?fn]]}]})
```

### Example: Write operations scoped to owned resources

```clojure
;; Token: session owns specific dashboard IDs
(sw/issue
  {:facts [[:invoke "dashboard/update"]
           [:owned-resource "dashboard" "dash-42"]
           [:owned-resource "dashboard" "dash-99"]]}
  {:private-key authority-key})

;; Enforcement: may update, but only dashboards you own
(sw/evaluate token
  :authorizer
  {:facts [[:requested-fn "dashboard/update"]
           [:requested-resource "dashboard" (:id args)]]
   :rules [{:id   :owns-target
            :head [:can-modify '?type '?id]
            :body [[:owned-resource '?type '?id]
                   [:requested-resource '?type '?id]]}]
   :policies [{:kind :allow
               :query [[:invoke "dashboard/update"]
                       [:can-modify "dashboard" '?id]]}]})
```

The pattern scales: simple whitelists stay simple (flat facts, no rules),
while parameter-level constraints add Datalog joins naturally. The
enforcement code is always the same — `sw/evaluate` with an authorizer
map. The complexity lives entirely in the token's facts and rules,
never in the deployment.

---

## Client-Side PEP in the Browser

The browser can run its own PEP before sending messages, using the
same dual-PEP architecture as the proxy scenario:

**Browser-side (outbound PEP):**
- Outbound token from the application authority
- Checks: approved server destinations, data classification, function restrictions
- Prevents the browser from sending messages it shouldn't (e.g., prompt
  injection causing a UI component to call an admin function)

**Server-side (inbound PEP):**
- Inbound token for this session
- Checks: function whitelist, parameter constraints, resource ownership
- Hard gate — drops unauthorized messages regardless of what the browser sends

The client-side PEP is defense in depth. The server-side PEP is the
load-bearing wall. Same as the AI agent architecture — the client
enforces its own policy, the server enforces the resource owner's policy,
neither trusts the other.

---

## Transport Properties

The RPC message carries everything the server needs to authorize:

| Property | Where it lives | Transport-independent? |
|---|---|---|
| Function name | Message body | Yes |
| Arguments | Message body | Yes |
| Authorization | Token (in message or session) | Yes |
| Integrity | Signed envelope | Yes |
| Freshness | UUIDv7 request-id | Yes |
| Audience | Signed envelope | Yes |

The websocket is just a pipe. The same messages could travel over
HTTP, SSE, message queues, or carrier pigeons. The security model
doesn't depend on the transport — it depends on the signatures and
the policy facts in the token.

For websocket connections specifically, there are two token delivery
options:

1. **Per-message**: token in each RPC message (fully stateless, like
   HTTP Bearer). Higher overhead, maximum independence.
2. **Session-scoped**: token presented at connection setup, cached
   server-side for the session duration. Lower overhead, requires
   session state. The server still verifies every message against
   the cached token — just doesn't re-parse it each time.

Both work. Option 2 is pragmatic for long-lived websocket sessions
where re-sending the token on every message would be wasteful.

---

## The Spectrum: From Open Eval to Capability-Gated RPC

```
Open nREPL          Simple whitelist         Datalog policy
════════════        ════════════════         ══════════════

Any fn, any args    Approved fns only       Approved fns with
                                            parameter constraints

Zero enforcement    [:invoke "fn"]          [:invoke "fn"]
                    token fact check        + [:allowed-symbol "X"]
                                            + [:owned-resource ...]
                                            + Datalog joins

💥 dangerous        ✓ safe baseline         ✓ fine-grained control
```

All three use the same `sw/evaluate` call, the same PEP pipeline,
the same deployment. Start with flat invoke facts. Add Datalog rules
when parameter-level policy becomes necessary. The enforcement code
never changes — only the token contents evolve.

---

*Document status: design reference.*
*Last updated: March 2026.*
*Related: `docs/datalog-as-authorization-join.md`,
`docs/dual-pep-client-server-enforcement.md` (in alpaca-clj)*
