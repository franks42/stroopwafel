# Stroopwafel

A Datalog engine for authorization decisions, in Clojure. Facts in,
decision out.

Since 0.11.0, stroopwafel is **only the engine**. It has no crypto, keys,
signatures, envelopes or wire formats, and no dependencies besides
Clojure. The rest of the stack lives in sibling libraries:

| Library                                                        | Role                                                                                                                                                                                                  |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **stroopwafel** (this)                                         | Datalog: facts, rules, checks, policies, scopes; `evaluate`                                                                                                                                           |
| [signet](https://github.com/franks42/signet)                   | crypto: keys, signing, signed envelopes, capability chains                                                                                                                                            |
| [stroopwafel-pdp](https://github.com/franks42/stroopwafel-pdp) | the decision point: verifies signed blocks with signet, turns them into facts and calls the engine. Includes an SPKI/SDSI assertion pipeline (sayer, validity, trust closure, delegation, revocation) |
| your PEP                                                       | enforces the decision in your wire format (HTTP, websocket, …)                                                                                                                                        |

The caller, normally stroopwafel-pdp, verifies signatures and extracts
facts _before_ calling `evaluate`. The engine trusts its input, so
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
  A pattern only matches facts of the same length. `sw/check-arity` lists
  predicates used with different lengths (almost always a typo: a reject
  check or deny policy that can never fire); run it on a policy set
  before storing it. `evaluate` reports them as `:warnings` by default;
  `:arity-check :error` denies instead, `:off` skips the check.
- **Rules** derive facts: `{:id :head [...] :body [[...] ...]}`, with
  optional `:when` guards and `:let` bindings. Rules run to a fixpoint,
  so recursive rules (transitive closure) work, within limits (below).
  Each round runs the blocks in order (0, 1, …, then the authorizer), and
  a block sees facts that earlier blocks derived in the same round. Since
  rule bodies have no negation and a fact keeps every origin set it is
  found with (see Scopes), this order never changes which facts each
  scope sees; it only affects how many rounds it takes, and which
  derivation `:explain? true` reports first.
- **Checks** must all pass. `{:id :query [...]}` passes if the query
  matches (check-if). `{:kind :reject ...}` passes if the query does _not_
  match (reject-if).
- **Policies** belong to the authorizer and run in order once all checks
  pass. The first match wins, whether `:allow` or `:deny`. If no policy
  matches, the result is deny (closed world), and so it is with no
  policies at all: only a matching `:allow` allows. The decision is always
  allow or deny, never a third outcome for the caller to interpret; the
  explain's `:reason` says why (`:no-matching-policy`, `:no-policies`, …),
  and no policies also adds a `{:type :no-policies}` warning. To let the
  checks alone decide, say so with `{:kind :allow :query []}`, which
  matches unconditionally. A caller that treats a missing policy set as
  an error can throw on the warning:

  ```clojure
  (let [result (sw/evaluate token :authorizer authz)]
    (when (some #(= :no-policies (:type %)) (:warnings result))
      (throw (ex-info "No policies" {:authorizer authz})))
    result)
  ```

  Only a malformed call throws: unknown options or authorizer keys
  (`:stroopwafel/error :unknown-keys`, so a typo like `:authoriser` can't
  silently drop the policies), and invalid `:limits` or `:arity-check`.
- **Scopes.** Every fact carries its set of origins: a block index or
  `:authorizer`. Block 0 is the authority. Block N's rules and checks see
  `#{0 N :authorizer}`. The authorizer sees `#{0 :authorizer}`. A later
  block can therefore add checks (restrict) but cannot add facts that the
  authorizer will see (expand). A fact stated or derived in several ways
  keeps each origin set, and a scope sees it through any of them, so a
  later block cannot hide a fact from the authorizer either (before
  0.14.0 it could: see
  `docs/security-advisory-2026-11-23-origin-hiding.md`).
- **Third-party blocks.** A block carries an `:external-key`. If that key
  is in the authorizer's `:trusted-external-keys`, the block's facts
  become visible to the authorizer, and the engine adds
  `[:block-signed-by idx key]`.
- **Expressions** in `:when` and `:let` are Clojure forms over a whitelist
  of about 35 functions: comparison, arithmetic, `str/…`, collections,
  type predicates, regex. There is no `eval` and no namespace lookup.
- **Explain.** `:explain? true` returns the whole decision: its
  `:result` and `:reason` (`:policy`, `:check-failed`,
  `:no-matching-policy`, `:no-policies`, `:limit-exceeded`,
  `:arity-mismatch`), every check with its block
  and result, every policy evaluated up to the deciding one, and one
  `:facts` table. A check's or policy's `:because` lists the facts it
  matched; `:facts` says for each fact which block stated it and which
  rules derived it (rule, block, bindings, and the facts the rule used),
  down to stated facts. `:explain? true` keeps the first derivation of
  each fact; `:explain? :all` keeps every derivation, circular ones
  included, up to `:max-derivations` (default 10 000; past it the
  explain is flagged `:truncated?`, the decision is unchanged).
  `sw/graph` turns it into decision, check, policy, fact and derivation
  nodes; a fact reached along several paths, or in a loop, is one node.

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
{:deps {com.github.franks42/stroopwafel {:mvn/version "0.15.0"}}}
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
