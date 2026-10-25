# Stroopwafel

A Datalog engine for authorization decisions, in Clojure. Facts in,
decision out.

Since 0.11.0, stroopwafel is **only the engine**. It has no crypto, keys,
signatures, envelopes or wire formats, and no dependencies besides
Clojure. The rest of the stack lives in sibling libraries:

| Library | Role |
|---|---|
| **stroopwafel** (this) | Datalog: facts, rules, checks, policies, scopes; `evaluate` |
| [signet](https://github.com/franks42/signet) | crypto: keys, signing, signed envelopes, capability chains |
| [stroopwafel-pdp](https://github.com/franks42/stroopwafel-pdp) | the decision point: verifies signed blocks with signet, turns them into facts and calls the engine. Includes an SPKI/SDSI assertion pipeline (sayer, validity, trust closure, delegation, revocation) |
| your PEP | enforces the decision in your wire format (HTTP, websocket, …) |

The caller, normally stroopwafel-pdp, verifies signatures and extracts
facts *before* calling `evaluate`. The engine trusts its input, so
everything that reaches it must already be verified.

Like a stroopwafel: two layers with something sealed between them.

## Example

```clojure
(require '[stroopwafel.core :as sw])

(def token
  {:blocks [;; block 0, the authority: rights and a rule
            {:facts [[:right "alice" :read "/api/data"]
                     [:right "alice" :write "/api/data"]]
             :rules '[{:id   :can
                       :head [:can ?u ?a ?r]
                       :body [[:right ?u ?a ?r]]}]}
            ;; block 1, an attenuation: only reads may pass
            {:checks '[{:id :read-only :query [[:can ?u :read ?r]]}]}]})

(sw/evaluate token
  :authorizer {:facts    [[:time 1000] [:request "alice" :read "/api/data"]]
               :checks   '[{:id    :not-expired
                            :query [[:time ?t]]
                            :when  [(< ?t 2000)]}]
               :policies '[{:kind  :allow
                            :query [[:request ?u ?a ?r] [:can ?u ?a ?r]]}]})
;; => {:valid? true}
;; with [:time 3000], or a request by "bob": {:valid? false}
```

## The model

- **Facts** are vectors, for example `[:right "alice" :read "/api/data"]`.
- **Rules** derive facts: `{:id :head [...] :body [[...] ...]}`, with
  optional `:when` guards and `:let` bindings. Rules run to a fixpoint,
  so recursive rules (transitive closure) work, within limits (below).
- **Checks** must all pass. `{:id :query [...]}` passes if the query
  matches (check-if). `{:kind :reject ...}` passes if the query does *not*
  match (reject-if).
- **Policies** belong to the authorizer and run in order once all checks
  pass. The first match wins, whether `:allow` or `:deny`. If no policy
  matches, the result is deny (closed world). If there are no policies at
  all, the result is allow.
- **Scopes.** Every fact carries its set of origins: a block index or
  `:authorizer`. Block 0 is the authority. Block N's rules and checks see
  `#{0 N :authorizer}`. The authorizer sees `#{0 :authorizer}`. A later
  block can therefore add checks (restrict) but cannot add facts that the
  authorizer will see (expand).
- **Third-party blocks.** A block carries an `:external-key`. If that key
  is in the authorizer's `:trusted-external-keys`, the block's facts
  become visible to the authorizer, and the engine adds
  `[:block-signed-by idx key]`.
- **Expressions** in `:when` and `:let` are Clojure forms over a whitelist
  of about 35 functions: comparison, arithmetic, `str/…`, collections,
  type predicates, regex. There is no `eval` and no namespace lookup.
- **Explain.** `:explain? true` returns a proof tree, and `sw/graph` turns
  it into nodes and edges.

## Limits fail closed

Rule evaluation is bounded: by default 100 rounds and 1000 facts (input
plus derived). If a limit is reached before the fixpoint, the decision
is a deny with a reason, and the partial store is never evaluated:

```clojure
;; chain: 50 edges and a transitive :reach rule (1325 facts at fixpoint);
;; deny: a :deny policy on [:reach 0 50], then an :allow
(sw/evaluate chain :authorizer deny)
;; => {:valid? false
;;     :error {:type :limit-exceeded :limit :max-facts :max 1000
;;             :facts 1025 :iterations 26}}
(sw/evaluate chain :authorizer deny :limits {:max-facts 5000})
;; => {:valid? false}   ; the fixpoint is reached, and the deny policy matches
```

A store cut short of its fixpoint is missing derived facts, so a
`:reject` check or a `:deny` policy over a missing fact would pass. Up to
0.11.0 that was what happened: evaluation stopped silently at a limit
and evaluated the partial store. It was reproduced on 2026-10-25 with
transitive closure over 50 edges (more than 1000 facts) and over 150
edges (more than 100 rounds); in both cases the deny policy allowed.
Unknown keys or non-positive values in `:limits` throw.

## SPKI/SDSI in Datalog

Binding an authorization to a key (SPKI) is a join between a fact the
issuer signed and a fact the PDP verified:

```clojure
(sw/evaluate {:blocks [{:facts [[:authorized-agent-key "urn:signet:pk:ed25519:abc"]]}]}
  :authorizer {:facts    [[:request-verified-agent-key "urn:signet:pk:ed25519:abc"]]
               :policies '[{:kind  :allow
                            :query [[:authorized-agent-key ?k]
                                    [:request-verified-agent-key ?k]]}]})
;; => {:valid? true}
```

Binding a name to keys (SDSI) is another join: `[:named-key "ops-team" ?k]`
with `[:right "ops-team" ?action ?resource]`. Two jobs belong outside the
engine: verifying the request signature that produces
`[:request-verified-agent-key …]` (signet) and deciding which signers to
trust (stroopwafel-pdp). The design is in
`docs/generic-assertion-schema.md`, where every fact becomes
`[sayer ts not-before not-after type id statement]`, and in
`docs/datalog-as-authorization-join.md`.

## Use

```clojure
;; deps.edn
{:deps {com.github.franks42/stroopwafel {:mvn/version "0.12.0"}}}
```

```sh
clojure -X:test        # the test suite
```

It also runs on babashka without changes: `bb -cp src`.

## Documentation

- `context.md`: current state, history, what moved where
- `docs/library-separation-plan.md`: the four layers (engine, signet, pdp, PEP)
- `docs/generic-assertion-schema.md`: the assertion tuple and the SPKI mapping
- `docs/datalog-as-authorization-join.md`: Datalog joins as SPKI 5-tuple reduction
- `docs/spki-sdsi-vs-biscuit.md`: SPKI/SDSI compared with Biscuit
- `docs/datalog-expressions-clj-design.md`: `:when` and `:let`
- `docs/stroopwafel-use-cases-examples.md`,
  `docs/how-to-let-llms-use-your-credit-card-securely.md` and
  `docs/websocket-rpc-enforcement.md` were written for the token API
  before 0.11 (issue, attenuate, seal). The ideas still hold; the code
  moved to signet and stroopwafel-pdp.

## Acknowledgments

Stroopwafel builds on [Biscuit](https://github.com/eclipse-biscuit/biscuit),
which provides signed, append-only authorization tokens with Datalog
policies. It is derived from [KEX](https://github.com/serefayar/kex),
Seref Ayar's proof of concept, which showed that these ideas can be
expressed naturally in Clojure.

## License

Copyright (c) Frank Siebenlist. Distributed under the [Eclipse Public License v2.0](LICENSE).
KEX attribution preserved per EPL-1.0.
