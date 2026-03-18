# Stroopwafel

Capability-based authorization tokens for Clojure.

Like a stroopwafel: two layers with something sealed between them — signed
blocks wrapping authorized data.

## What It Does

Stroopwafel issues cryptographically signed tokens that carry their own
authorization logic. Each token is an append-only chain of Ed25519-signed
blocks containing Datalog facts, rules, and checks. Tokens can be
attenuated (delegated with reduced authority), sealed (frozen), and
evaluated against an authorizer's context — all without a central server.

```clojure
(require '[stroopwafel.core :as sw])

;; Authority issues a token
(def root-kp (sw/new-keypair))
(def token
  (sw/issue {:facts [[:right "alice" :read "/api/data"]
                     [:right "alice" :write "/api/data"]]
             :checks '[{:id    :check-expiry
                        :query [[:time ?t]]
                        :when  [(< ?t 1735689600000)]}]}
            {:private-key (:priv root-kp)}))

;; Delegate with reduced authority (read-only)
(def restricted
  (sw/attenuate token
    {:checks '[{:id :read-only :query [[:right ?u :read ?r]]}]}))

;; Verify and evaluate
(sw/verify restricted {:public-key (:pub root-kp)})
;; => true

(sw/evaluate restricted
  :authorizer {:facts    [[:time (System/currentTimeMillis)]
                          [:resource "/api/data"]]
               :policies '[{:kind :allow
                             :query [[:right "alice" :read ?r]]}]})
;; => {:valid? true}
```

## Features

- **Ed25519 signature chains** — append-only blocks, each signed with ephemeral keys
- **Datalog authorization** — facts, rules, checks, and policies with scoped evaluation
- **Block isolation** — delegated blocks can only restrict authority, never expand it
- **Deny rules** — negative constraints (reject-if)
- **Authorizer policies** — ordered allow/deny, first match wins, closed-world default
- **Expressions** — `:when` guards and `:let` bindings with ~35 whitelisted built-in functions
- **Sealed tokens** — freeze to prevent further attenuation
- **Third-party blocks** — external parties sign blocks bound to a specific token
- **Revocation IDs** — SHA-256 of block signatures for revocation sets
- **Requester-bound tokens** — proof-of-possession via signed requests (see below)
- **Runs on JVM and Babashka** — full test suite passes on both

## Dependencies

Clojure + [CEDN](https://github.com/franks42/canonical-edn) (deterministic EDN serialization). No Protobuf, no external crypto libraries — JCA only.

```clojure
;; deps.edn
{:deps {com.github.franks42/stroopwafel {:mvn/version "0.9.0"}
        com.github.franks42/cedn {:mvn/version "1.2.0"}}}
```

## Requester-Bound Tokens

### The Problem with Bearer Tokens

A normal token is a bearer token — anyone who holds it can use it. If an
attacker intercepts the token (network sniff, log leak, compromised process),
they can present it as their own. The token can't tell who's presenting it.

### Binding a Token to a Key

The authority binds the token to a specific agent's public key at issuance:

```clojure
(require '[stroopwafel.request :as req]
         '[stroopwafel.crypto :as crypto])

(def agent-kp (sw/new-keypair))
(def agent-pk-bytes (crypto/encode-public-key (:pub agent-kp)))

(def token
  (sw/issue {:facts [[:authorized-agent-key agent-pk-bytes]
                     [:resource "/api/transfer"]
                     [:limit 1000]]}
            {:private-key (:priv root-kp)}))
```

Now the token says: "whoever presents this must prove they hold the private
key matching `agent-pk-bytes`."

### Signing Requests

The agent signs every request with its private key:

```clojure
(def signed-req
  (req/sign-request {:action :transfer :amount 500}
                    (:priv agent-kp) (:pub agent-kp)))
;; => {:body {...} :agent-key <bytes> :sig <bytes> :timestamp 1742...}
```

### Verifying: Signature + Token Together

The execution service verifies the request signature, then tells the Datalog
engine who actually made the request:

```clojure
(let [verified-key (req/verify-request signed-req)]
  (sw/evaluate token
    :authorizer
    {:facts [[:request-verified-agent-key verified-key]]
     :rules '[{:id   :agent-bound
               :head [:agent-can-act ?k]
               :body [[:authorized-agent-key ?k]
                      [:request-verified-agent-key ?k]]}]
     :policies '[{:kind :allow :query [[:agent-can-act ?k]]}]}))
;; => {:valid? true}
```

The Datalog join `[:authorized-agent-key ?k]` + `[:request-verified-agent-key ?k]`
is the key insight. Both facts must bind `?k` to the **same** public key bytes.
The first comes from the token (signed by the authority). The second comes from
verifying the request signature. If an attacker steals the token but doesn't
have the agent's private key, they can't produce a valid signature, so the
join fails and authorization is denied.

### What This Means

**Token theft is neutralized.** The token alone is worthless without the
corresponding private key.

**Capabilities compose with identity.** A token can say "agent X can spend
up to $1000 on office supplies" — the spending limit is a capability
restriction (Datalog check), and the agent binding is cryptographic.
Attenuation still works: delegated blocks can further restrict the amount,
but can't change which agent the token is bound to.

**No separate authentication protocol.** The signed request is both
authentication and authorization — one round trip, one verification.

### The SPKI Connection

This is exactly what [SPKI/SDSI](https://datatracker.ietf.org/doc/html/rfc2693)
certificates did in 1996: bind an authorization directly to a public key, not
to a name. The industry went through 25 years of bearer tokens (OAuth 2.0),
realized bearer is insufficient, and is now adding proof-of-possession back
([DPoP](https://datatracker.ietf.org/doc/html/rfc9449) in 2023,
[GNAP](https://datatracker.ietf.org/doc/html/rfc9635) in 2024). Stroopwafel
expresses SPKI's model as Datalog facts instead of certificate fields.

## SDSI Name Binding (Groups)

The examples above bind a token to one specific key (pure SPKI). SDSI adds
the other half: **name→key mappings**. Instead of binding entitlements to a
key, bind them to a *name* — then separately define which keys belong to
that name.

### One Token, Many Agents

Issue a single token with entitlements for a named group:

```clojure
(def token
  (sw/issue {:facts [[:right "ops-team" :read "/api/metrics"]
                     [:right "ops-team" :restart "/api/service"]]}
            {:private-key (:priv root-kp)}))
```

The token says nothing about specific keys. The authorizer maintains the
group roster as name→key bindings:

```clojure
(sw/evaluate token
  :authorizer
  {:facts [[:request-verified-agent-key verified-key]
           ;; SDSI name bindings — the group roster
           [:named-key "ops-team" alice-pk-bytes]
           [:named-key "ops-team" bob-pk-bytes]]
   :rules '[{:id   :resolve-name
             :head [:authenticated-as ?name]
             :body [[:named-key ?name ?k]
                    [:request-verified-agent-key ?k]]}]
   :policies '[{:kind  :allow
                :query [[:authenticated-as ?name]
                        [:right ?name ?action ?resource]]}]})
```

The Datalog chain: `[:named-key ?name ?k]` binds the verified key to a name,
then `[:right ?name ?action ?resource]` checks the name's entitlements.
Adding or removing group members is just updating the authorizer's name
bindings — no token reissuance needed.

### Where Name Bindings Can Live

| Source | How | Best for |
|--------|-----|----------|
| **Authorizer facts** | Execution service maintains the roster | Simple setups, internal services |
| **Third-party blocks** | IdP signs `[:named-key "group" pk]` | Federated identity, cross-org |
| **Authority block** | Issuer pre-registers keys at issuance | Static groups, air-gapped systems |

Third-party blocks are the most powerful option — an external IdP can attest
group membership without the authority or execution service knowing the
member list in advance:

```clojure
;; IdP signs a third-party block with the name→key binding
(def tp-block
  (sw/create-third-party-block
    (sw/third-party-request token)
    {:facts [[:named-key "verified-users" agent-pk-bytes]]}
    {:private-key (:priv idp-sk) :public-key (:pub idp-kp)}))

(def token2 (sw/append-third-party token tp-block))

;; Authorizer trusts the IdP
(sw/evaluate token2
  :authorizer {:trusted-external-keys [(:pub idp-kp)]
               ...})
```

### SPKI + SDSI = Full Model

| Layer | What it does | Stroopwafel expression |
|-------|-------------|----------------------|
| **SPKI** | Authorization bound to key | `[:authorized-agent-key pk]` + signed request |
| **SDSI** | Name bound to key | `[:named-key "group" pk]` + signed request |
| **Capability** | What the name/key can do | `[:right "group" :action "/resource"]` |
| **Datalog join** | Chains it all together | Rules unify `?k` across name, request, and entitlement |

This is the [SPKI/SDSI](https://datatracker.ietf.org/doc/html/rfc2693) model
from 1996, expressed as Datalog facts. No new code was needed — the Datalog
engine's join semantics and the signed request primitives compose naturally.

## Documentation

- `context.md` — full architecture and design decisions
- `docs/stroopwafel-use-cases-examples.md` — 4 worked use cases with REPL snippets
- `docs/how-to-let-llms-use-your-credit-card-securely.md` — AI agent transaction security
- `docs/spki-sdsi-vs-biscuit.md` — SPKI/SDSI vs Biscuit comparison
- `docs/datalog-expressions-clj-design.md` — expression design doc
- `docs/biscuit-gap-analysis.md` — feature parity status

## Acknowledgments

Stroopwafel builds on the vision of [Biscuit](https://github.com/eclipse-biscuit/biscuit) —
cryptographically signed, append-only authorization tokens with Datalog-based
policy evaluation — and is derived from [KEX](https://github.com/serefayar/kex),
Seref Ayar's elegant proof-of-concept that demonstrated these ideas can be
expressed naturally in Clojure. Stroopwafel aims to bring KEX to production
quality with full Biscuit feature parity, using
[CEDN](https://github.com/franks42/canonical-edn) for deterministic serialization.

## License

Copyright (c) Frank Siebenlist. Distributed under the [Eclipse Public License v2.0](LICENSE).
KEX attribution preserved per EPL-1.0.
