# Stroopwafel: context

## What this is (0.12.0)

Stroopwafel is a pure Datalog engine for authorization decisions. Facts,
rules, checks and policies go in; `{:valid? …}` comes out. It has no
crypto and no dependencies besides Clojure, and it runs on the JVM and
on babashka.

Until 0.10.2 stroopwafel was a complete Biscuit-style token library:
signed block chains, ephemeral keys, sealing, signed requests, a PEP
pipeline, and replay protection. In April 2026 it was split into four
layers (`docs/library-separation-plan.md`):

| Layer               | Contents                                                                                                                                                               | Depends on          |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| **stroopwafel**     | `core.clj` (`evaluate`), `datalog.clj` (the engine), `graph.clj` (explain → graph)                                                                                     | Clojure             |
| **signet**          | keys, signing, signed envelopes, capability chains, SSH key import                                                                                                     | cedn, uuidv7, …     |
| **stroopwafel-pdp** | verifies signed blocks or chains, turns them into facts, calls the engine; trust roots, replay protection; the SPKI/SDSI assertion pipeline (`stroopwafel.pdp.spki.*`) | signet, stroopwafel |
| **application PEP** | enforces the decision in a wire format (for example alpaca-clj over HTTP)                                                                                              | stroopwafel-pdp     |

Where the old namespaces went (commit `68c03ff`): crypto, envelope, ssh
and chain moved to signet. replay, trust and pep moved to
stroopwafel-pdp. Request canonicalization became consumer-specific
(`alpaca.pep.http-edn`).

**Name origin:** cookie → biscuit → kex (Swedish) → stroopwafel (Dutch).

## The engine

`stroopwafel.core/evaluate` takes `{:blocks [{:facts :rules :checks
:external-key?} …]}` and the keyword args `:authorizer {:facts :rules
:checks :policies :trusted-external-keys}` and `:explain?`. The caller
must have verified every block already, because the engine trusts its
input.

1. **Origins and scopes.** Every fact carries a set of origins: its block
   index, or `:authorizer`. A derived fact carries the union of its inputs'
   origins plus the deriving rule's block. Block 0 (the authority) and
   the authorizer see `#{0 :authorizer}`. Block N sees `#{0 N
   :authorizer}`. This is Biscuit's guarantee: later blocks can restrict
   authority but never expand it.
2. **Rules** run to a fixpoint, so recursion and transitive closure work.
   `:limits` (default `{:max-iterations 100 :max-facts 1000}`) bound it.
   Reaching a limit first throws inside `apply-rules-scoped`, and
   `eval-token` turns that into `{:valid? false :error {:type
   :limit-exceeded …}}`: a partial store is never evaluated, because a
   reject check or deny policy over a missing derived fact would pass.
3. **Checks.** `:one` (the default, check-if) passes on a match. `:reject`
   (reject-if) passes when there is no match. Rule bodies have no
   negation; negative constraints are expressed as reject checks and deny
   policies.
4. **Policies** belong to the authorizer and run in order after all checks
   pass. The first match wins. If none matches, the result is deny (closed
   world). If there are no policies at all, the result is allow.
5. **Third-party blocks.** A block's `:external-key` that appears in
   `:trusted-external-keys` makes that block visible to the authorizer and
   adds `[:block-signed-by idx key]`.
6. **Expressions.** `:when` guards and `:let` bindings are Clojure forms
   over a closed whitelist of about 35 functions, with no `eval` and no
   resolve. Evaluation order: pattern match, then `:let`, then `:when`,
   then instantiate the head. See `docs/datalog-expressions-clj-design.md`.
7. **Byte-array-aware unification** (`value=`), so keys as bytes still
   join. Sayers in the pdp's SPKI path are kid URN strings.

## The SPKI/SDSI direction

`docs/generic-assertion-schema.md` (April 2026) makes every fact an
assertion `[sayer ts not-before not-after type id statement]`.
Authorization is then the reduction of mutually consistent assertions to
"self asserts this action is permitted". stroopwafel-pdp implements it:

- signed assertion blocks (a signet envelope whose message is
  `{:not-before :not-after :assertions [{:id :type :statement}]}`);
- a pre-filter: signature, then validity (with a verifier cap), then trust
  closure from the trust roots through delegation, then a per-assertion
  trust check, then revocation, then expansion into 7-position facts;
- template rules for `:capability`, `:name-binding`, `:delegation` and
  `:revocation`.

The trust anchor `:self` (the local PDP, the only axiomatic sayer:
`[:trusted :self]`, with trust roots as `:self` assertions) is sketched in
`stroopwafel-tutorial/notebooks/00_new_model_sketch.clj`. It isn't in the
code yet.

## Known issues and open work

- **Fixed in 0.12.0 (2026-10-25): the fixpoint limit failed open.**
  Up to 0.11.0, evaluation stopped silently at 100 iterations or 1000
  facts and evaluated the partial store, so `:reject` checks and `:deny`
  policies over missing derived facts passed. It was reproduced with
  transitive closure over 50 edges (facts) and 150 edges (iterations).
  Now a limit denies with `:error`, and limits are configurable.
  Tests: `deny-policy-fails-closed-at-fact-limit`,
  `reject-check-fails-closed-at-fact-limit`,
  `fails-closed-at-iteration-limit`, `limits-are-configurable`,
  `evaluate-fails-closed-at-a-limit`. `fact-explosion-capped` became
  `fact-explosion-fails-closed`: it expected the truncated store to still
  allow `[:n 100]`. stroopwafel-pdp maps the result to `{:allowed?
  false}` but doesn't pass `:error` on yet.
- **Key cards and self-scoped assertions** (from signet docs/14, "Key
  cards", and signet `docs/tutorial/TODO.md`):
  - admit statements a key makes about itself without trust;
  - keep the sayer on name bindings (`[:named ?sayer ?key ?name]`);
  - join multi-signed cards on the message digest;
  - use `:self` as the sayer of injected and derived facts.
  These mostly concern stroopwafel-pdp.
- **Docs written for the pre-0.11 API** (use cases, LLM credit card,
  websocket RPC) still show `issue`, `attenuate` and `seal`. Their ideas
  hold; their code moved.
- **ClojureScript.** The engine is plain Clojure and could become `.cljc`
  without changes to its logic. Not started.

## History

| Version | What                                                                                             |
| ------- | ------------------------------------------------------------------------------------------------ |
| 0.1.0   | KEX copied in; CEDN canonical bytes replace `pr-str`; 27 KEX tests green                         |
| 0.2.0   | origin sets, scope isolation, fixpoint rules, reject checks, authorizer context                  |
| 0.3.0   | revocation IDs, authorizer policies, ephemeral keys per block                                    |
| 0.4.0   | sealed tokens                                                                                    |
| 0.5.0   | `:when` / `:let` expressions                                                                     |
| 0.6.0   | third-party blocks                                                                               |
| 0.7.0   | babashka compatibility                                                                           |
| 0.8.0   | requester-bound tokens (SPKI join of a signed fact and a verified request key)                   |
| 0.9.0   | multi-token authorization, SDSI name-binding patterns, delegation chains, fixpoint safety tests  |
| 0.10.0  | signed envelopes, PEP pipeline, replay guard, trust-root facts, SSH key import (from alpaca-clj) |
| 0.10.2  | blocks as unified signed envelopes                                                               |
| 0.11.0  | stripped to the pure engine; everything else moved to signet and stroopwafel-pdp; 66 tests       |
| 0.12.0  | fixpoint limits fail closed (deny with `:error`) and are configurable (`:limits`); 71 tests      |

## Lineage

- **KEX** (Seref Ayar, EPL-1.0, about 470 lines) gave the skeleton:
  core, datalog, block, crypto, graph. It was copied rather than forked,
  because the changes were too fundamental for upstream.
- **Biscuit** gave the target feature set: authority and attenuation
  blocks, scoped Datalog, checks and policies, third-party blocks,
  revocation. Local reference clones: `../biscuit/`, `../biscuit-java/`,
  `../biscuit-rust/`, `../biscuit-cli/`.
- **CEDN** (`com.github.franks42/cedn`) gave deterministic serialization
  for signing. Since 0.11.0 it is signet's dependency, not this library's.
- **SPKI/SDSI** (RFC 2693) is the model the assertion schema expresses as
  Datalog: `docs/spki-sdsi-vs-biscuit.md`,
  `docs/datalog-as-authorization-join.md`.

## License

EPL-2.0. KEX attribution preserved per EPL-1.0.
