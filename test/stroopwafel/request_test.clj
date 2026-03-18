(ns stroopwafel.request-test
  (:require [stroopwafel.request :as req]
            [stroopwafel.core :as sw]
            [stroopwafel.crypto :as crypto]
            [clojure.test :as t]))

;; --- sign-request / verify-request ---

(t/deftest sign-verify-round-trip
  (t/testing "Signed request verifies with correct key"
    (let [agent-kp (sw/new-keypair)
          signed   (req/sign-request {:action :transfer :amount 500}
                                     (:priv agent-kp) (:pub agent-kp))
          result   (req/verify-request signed)]
      (t/is (some? result))
      (t/is (crypto/bytes= result (crypto/encode-public-key (:pub agent-kp)))))))

(t/deftest verify-rejects-tampered-body
  (t/testing "Tampered body fails verification"
    (let [agent-kp (sw/new-keypair)
          signed   (req/sign-request {:action :transfer :amount 500}
                                     (:priv agent-kp) (:pub agent-kp))
          tampered (assoc signed :body {:action :transfer :amount 999})]
      (t/is (nil? (req/verify-request tampered))))))

(t/deftest verify-rejects-wrong-key
  (t/testing "Request signed by different agent fails verification"
    (let [agent-kp   (sw/new-keypair)
          attacker   (sw/new-keypair)
          ;; Attacker signs with their key but claims to be agent
          signed     (req/sign-request {:action :transfer :amount 500}
                                       (:priv attacker) (:pub attacker))
          ;; Swap in agent's key to impersonate
          forged     (assoc signed :agent-key
                           (crypto/encode-public-key (:pub agent-kp)))]
      (t/is (nil? (req/verify-request forged))))))

(t/deftest signed-request-has-timestamp
  (t/testing "Signed request includes a timestamp"
    (let [agent-kp (sw/new-keypair)
          before   (System/currentTimeMillis)
          signed   (req/sign-request {:x 1} (:priv agent-kp) (:pub agent-kp))
          after    (System/currentTimeMillis)]
      (t/is (<= before (:timestamp signed) after)))))

;; --- Full integration: signed request + token Datalog join ---

(t/deftest requester-bound-token-allows-authorized-agent
  (t/testing "Token with agent key binding allows matching signed request"
    (let [root-kp  (sw/new-keypair)
          agent-kp (sw/new-keypair)
          agent-pk-bytes (crypto/encode-public-key (:pub agent-kp))

          ;; Issue token bound to this agent
          token (sw/issue
                 {:facts [[:authorized-agent-key agent-pk-bytes]
                          [:resource "/api/transfer"]
                          [:limit 1000]]}
                 {:private-key (:priv root-kp)})

          ;; Agent signs a request
          signed (req/sign-request {:action :transfer :amount 500}
                                   (:priv agent-kp) (:pub agent-kp))

          ;; Execution service verifies request signature
          verified-key (req/verify-request signed)

          ;; Evaluate token with verified agent identity
          result (sw/evaluate token
                   :authorizer
                   {:facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :agent-bound
                              :head [:agent-can-act ?k]
                              :body [[:authorized-agent-key ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind :allow
                                 :query [[:agent-can-act ?k]]}]})]
      (t/is (some? verified-key))
      (t/is (:valid? result)))))

(t/deftest requester-bound-token-rejects-wrong-agent
  (t/testing "Token rejects request signed by unauthorized agent"
    (let [root-kp     (sw/new-keypair)
          agent-kp    (sw/new-keypair)
          attacker-kp (sw/new-keypair)
          agent-pk-bytes (crypto/encode-public-key (:pub agent-kp))

          ;; Token bound to agent
          token (sw/issue
                 {:facts [[:authorized-agent-key agent-pk-bytes]
                          [:resource "/api/transfer"]]}
                 {:private-key (:priv root-kp)})

          ;; Attacker signs request with their own key
          signed (req/sign-request {:action :transfer :amount 500}
                                   (:priv attacker-kp) (:pub attacker-kp))
          verified-key (req/verify-request signed)

          ;; Evaluate — keys don't match, Datalog join fails
          result (sw/evaluate token
                   :authorizer
                   {:facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :agent-bound
                              :head [:agent-can-act ?k]
                              :body [[:authorized-agent-key ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind :allow
                                 :query [[:agent-can-act ?k]]}]})]
      ;; Signature is valid (attacker used their own key correctly)
      (t/is (some? verified-key))
      ;; But authorization fails — wrong agent
      (t/is (not (:valid? result))))))

(t/deftest requester-bound-token-with-attenuation
  (t/testing "Attenuated token preserves agent binding from authority block"
    (let [root-kp  (sw/new-keypair)
          agent-kp (sw/new-keypair)
          agent-pk-bytes (crypto/encode-public-key (:pub agent-kp))

          ;; Issue token bound to agent with broad rights
          token (sw/issue
                 {:facts [[:authorized-agent-key agent-pk-bytes]
                          [:right :read "/api/data"]
                          [:right :write "/api/data"]]}
                 {:private-key (:priv root-kp)})

          ;; Attenuate: restrict to read-only
          restricted (sw/attenuate token
                       {:checks '[{:id    :read-only
                                   :query [[:right :read ?r]]}]})

          ;; Agent signs request
          signed (req/sign-request {:action :read :path "/api/data"}
                                   (:priv agent-kp) (:pub agent-kp))
          verified-key (req/verify-request signed)

          result (sw/evaluate restricted
                   :authorizer
                   {:facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :agent-bound
                              :head [:agent-can-act ?k]
                              :body [[:authorized-agent-key ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind :allow
                                 :query [[:agent-can-act ?k]]}]})]
      (t/is (:valid? result)))))

(t/deftest requester-bound-token-with-expression-guard
  (t/testing "Agent binding works with :when expression guard on amount"
    (let [root-kp  (sw/new-keypair)
          agent-kp (sw/new-keypair)
          agent-pk-bytes (crypto/encode-public-key (:pub agent-kp))

          token (sw/issue
                 {:facts [[:authorized-agent-key agent-pk-bytes]
                          [:limit 1000]]}
                 {:private-key (:priv root-kp)})

          signed (req/sign-request {:action :transfer :amount 500}
                                   (:priv agent-kp) (:pub agent-kp))
          verified-key (req/verify-request signed)

          result (sw/evaluate token
                   :authorizer
                   {:facts [[:request-verified-agent-key verified-key]
                            [:request-amount 500]]
                    :rules '[{:id   :agent-bound
                              :head [:agent-can-act ?k]
                              :body [[:authorized-agent-key ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind  :allow
                                 :query [[:agent-can-act ?k]
                                         [:limit ?max]
                                         [:request-amount ?amt]]
                                 :when  [(<= ?amt ?max)]}]})]
      (t/is (:valid? result)))))

;; --- SDSI name binding: name→key mapping + name-based entitlements ---

(defn- make-sdsi-authorizer
  "Builds an authorizer with SDSI name bindings (group roster)
   and the verified request key."
  [verified-key named-keys]
  {:facts (into [[:request-verified-agent-key verified-key]]
                named-keys)
   :rules '[{:id   :resolve-name
             :head [:authenticated-as ?name]
             :body [[:named-key ?name ?k]
                    [:request-verified-agent-key ?k]]}]
   :policies '[{:kind  :allow
                :query [[:authenticated-as ?name]
                        [:right ?name ?action ?resource]]}]})

(t/deftest sdsi-name-binding-allows-group-member
  (t/testing "Agent in named group is authorized via name→key binding"
    (let [root-kp  (sw/new-keypair)
          agent-a  (sw/new-keypair)
          agent-b  (sw/new-keypair)
          pk-a     (crypto/encode-public-key (:pub agent-a))
          pk-b     (crypto/encode-public-key (:pub agent-b))

          ;; Token grants entitlements to a name, not a key
          token (sw/issue
                 {:facts [[:right "ops-team" :read "/api/metrics"]
                          [:right "ops-team" :restart "/api/service"]]}
                 {:private-key (:priv root-kp)})

          ;; Agent A signs request
          signed (req/sign-request {:action :read} (:priv agent-a) (:pub agent-a))
          verified-key (req/verify-request signed)

          result (sw/evaluate token
                   :authorizer (make-sdsi-authorizer verified-key
                                 [[:named-key "ops-team" pk-a]
                                  [:named-key "ops-team" pk-b]]))]
      (t/is (:valid? result)))))

(t/deftest sdsi-name-binding-rejects-non-member
  (t/testing "Agent not in named group is rejected"
    (let [root-kp   (sw/new-keypair)
          member    (sw/new-keypair)
          outsider  (sw/new-keypair)
          pk-member (crypto/encode-public-key (:pub member))

          token (sw/issue
                 {:facts [[:right "ops-team" :read "/api/metrics"]]}
                 {:private-key (:priv root-kp)})

          ;; Outsider signs request
          signed (req/sign-request {:action :read} (:priv outsider) (:pub outsider))
          verified-key (req/verify-request signed)

          result (sw/evaluate token
                   :authorizer (make-sdsi-authorizer verified-key
                                 [[:named-key "ops-team" pk-member]]))]
      (t/is (not (:valid? result))))))

(t/deftest sdsi-multiple-groups
  (t/testing "Agent in one group gets only that group's entitlements"
    (let [root-kp (sw/new-keypair)
          alice   (sw/new-keypair)
          bob     (sw/new-keypair)
          pk-a    (crypto/encode-public-key (:pub alice))
          pk-b    (crypto/encode-public-key (:pub bob))

          ;; Token with entitlements for two groups
          token (sw/issue
                 {:facts [[:right "readers" :read "/api/data"]
                          [:right "writers" :write "/api/data"]]}
                 {:private-key (:priv root-kp)})

          ;; Alice is a reader, Bob is a writer
          signed-a (req/sign-request {:action :read} (:priv alice) (:pub alice))
          verified-a (req/verify-request signed-a)

          name-bindings [[:named-key "readers" pk-a]
                         [:named-key "writers" pk-b]]

          ;; Alice can read
          result-a (sw/evaluate token
                     :authorizer (make-sdsi-authorizer verified-a name-bindings))

          ;; Bob signs
          signed-b (req/sign-request {:action :write} (:priv bob) (:pub bob))
          verified-b (req/verify-request signed-b)

          ;; Bob can write
          result-b (sw/evaluate token
                     :authorizer (make-sdsi-authorizer verified-b name-bindings))]

      ;; Both succeed — each resolves to their own group
      (t/is (:valid? result-a))
      (t/is (:valid? result-b)))))

(t/deftest sdsi-name-binding-with-attenuation
  (t/testing "Attenuated token restricts name-based entitlements"
    (let [root-kp (sw/new-keypair)
          agent   (sw/new-keypair)
          pk      (crypto/encode-public-key (:pub agent))

          ;; Broad token
          token (sw/issue
                 {:facts [[:right "ops-team" :read "/api/metrics"]
                          [:right "ops-team" :restart "/api/service"]]}
                 {:private-key (:priv root-kp)})

          ;; Attenuate: read-only
          restricted (sw/attenuate token
                       {:checks '[{:id :read-only
                                   :query [[:right ?name :read ?r]]}]})

          signed (req/sign-request {:action :read} (:priv agent) (:pub agent))
          verified-key (req/verify-request signed)

          result (sw/evaluate restricted
                   :authorizer (make-sdsi-authorizer verified-key
                                 [[:named-key "ops-team" pk]]))]
      (t/is (:valid? result)))))

(t/deftest sdsi-name-binding-via-third-party-block
  (t/testing "IdP attests group membership via third-party block"
    (let [root-kp (sw/new-keypair)
          idp-kp  (sw/new-keypair)
          agent   (sw/new-keypair)
          pk      (crypto/encode-public-key (:pub agent))

          ;; Token with name-based entitlements
          token (sw/issue
                 {:facts [[:right "verified-users" :read "/api/data"]]}
                 {:private-key (:priv root-kp)})

          ;; IdP signs a third-party block attesting the name→key binding
          tp-req (sw/third-party-request token)
          tp-block (sw/create-third-party-block
                     tp-req
                     {:facts [[:named-key "verified-users" pk]]}
                     {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})
          token2 (sw/append-third-party token tp-block)

          ;; Agent signs request
          signed (req/sign-request {:action :read} (:priv agent) (:pub agent))
          verified-key (req/verify-request signed)

          ;; Authorizer trusts IdP and evaluates
          result (sw/evaluate token2
                   :authorizer
                   {:trusted-external-keys [(:pub idp-kp)]
                    :facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :resolve-name
                              :head [:authenticated-as ?name]
                              :body [[:named-key ?name ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind  :allow
                                 :query [[:authenticated-as ?name]
                                         [:right ?name :read ?r]]}]})]
      (t/is (:valid? result)))))

;; --- Delegation chains: authority delegates naming power ---

(t/deftest delegation-authority-trusts-idp-for-naming
  (t/testing "Root delegates naming power to IdP via [:can-name group signer-key]"
    (let [root-kp (sw/new-keypair)
          idp-kp  (sw/new-keypair)
          agent   (sw/new-keypair)
          idp-pk  (crypto/encode-public-key (:pub idp-kp))
          agent-pk (crypto/encode-public-key (:pub agent))

          ;; Root authority: grants entitlements + delegates naming to IdP
          token (sw/issue
                 {:facts [[:right "authorized-client" :read "/api/data"]
                          [:right "authorized-client" :write "/api/data"]
                          [:can-name "authorized-client" idp-pk]]}
                 {:private-key (:priv root-kp)})

          ;; IdP signs third-party block asserting group membership
          tp-req (sw/third-party-request token)
          tp-block (sw/create-third-party-block
                     tp-req
                     {:facts [[:named-key "authorized-client" agent-pk]]}
                     {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})
          token2 (sw/append-third-party token tp-block)

          ;; Agent signs request
          signed (req/sign-request {:action :read} (:priv agent) (:pub agent))
          verified-key (req/verify-request signed)

          ;; Authorizer uses delegation chain:
          ;; block-signed-by links signer to can-name, validates named-key
          result (sw/evaluate token2
                   :authorizer
                   {:trusted-external-keys [(:pub idp-kp)]
                    :facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :delegated-naming
                              :head [:member ?group ?agent-key]
                              :body [[:block-signed-by ?idx ?signer]
                                     [:can-name ?group ?signer]
                                     [:named-key ?group ?agent-key]]}
                             {:id   :resolve-member
                              :head [:authenticated-as ?group]
                              :body [[:member ?group ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind  :allow
                                 :query [[:authenticated-as ?name]
                                         [:right ?name ?action ?r]]}]})]
      (t/is (:valid? result)))))

(t/deftest delegation-rejects-untrusted-naming-authority
  (t/testing "Third-party block from non-delegated signer is rejected by Datalog"
    (let [root-kp    (sw/new-keypair)
          idp-kp     (sw/new-keypair)
          rogue-kp   (sw/new-keypair)
          agent      (sw/new-keypair)
          idp-pk     (crypto/encode-public-key (:pub idp-kp))
          agent-pk   (crypto/encode-public-key (:pub agent))

          ;; Root delegates naming ONLY to idp
          token (sw/issue
                 {:facts [[:right "authorized-client" :read "/api/data"]
                          [:can-name "authorized-client" idp-pk]]}
                 {:private-key (:priv root-kp)})

          ;; Rogue signs a third-party block claiming membership
          tp-req (sw/third-party-request token)
          tp-block (sw/create-third-party-block
                     tp-req
                     {:facts [[:named-key "authorized-client" agent-pk]]}
                     {:private-key (:priv rogue-kp) :public-key (:pub rogue-kp)})
          token2 (sw/append-third-party token tp-block)

          signed (req/sign-request {:action :read} (:priv agent) (:pub agent))
          verified-key (req/verify-request signed)

          ;; Authorizer trusts rogue's key (crypto passes) but
          ;; Datalog rejects: rogue-pk not in [:can-name ...] facts
          result (sw/evaluate token2
                   :authorizer
                   {:trusted-external-keys [(:pub rogue-kp)]
                    :facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :delegated-naming
                              :head [:member ?group ?agent-key]
                              :body [[:block-signed-by ?idx ?signer]
                                     [:can-name ?group ?signer]
                                     [:named-key ?group ?agent-key]]}
                             {:id   :resolve-member
                              :head [:authenticated-as ?group]
                              :body [[:member ?group ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind  :allow
                                 :query [[:authenticated-as ?name]
                                         [:right ?name ?action ?r]]}]})]
      (t/is (not (:valid? result))))))

(t/deftest delegation-circular-trust-no-bootstrap
  (t/testing "Circular delegation with no ground truth produces nothing"
    (let [root-kp  (sw/new-keypair)
          idp-kp   (sw/new-keypair)
          agent    (sw/new-keypair)
          agent-pk (crypto/encode-public-key (:pub agent))

          ;; Circular: group-a trusts group-b for naming, group-b trusts group-a
          ;; No one is in either group — no bootstrap, chain can't start
          token (sw/issue
                 {:facts [[:right "group-a" :read "/data"]
                          [:can-name-if-member "group-a" "group-b"]
                          [:can-name-if-member "group-b" "group-a"]]}
                 {:private-key (:priv root-kp)})

          tp-req (sw/third-party-request token)
          tp-block (sw/create-third-party-block
                     tp-req
                     {:facts [[:named-key "group-a" agent-pk]]}
                     {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})
          token2 (sw/append-third-party token tp-block)

          signed (req/sign-request {:action :read} (:priv agent) (:pub agent))
          verified-key (req/verify-request signed)

          result (sw/evaluate token2
                   :authorizer
                   {:trusted-external-keys [(:pub idp-kp)]
                    :facts [[:request-verified-agent-key verified-key]]
                    :rules '[{:id   :trust-chain
                              :head [:can-name ?tg ?signer]
                              :body [[:can-name-if-member ?tg ?ag]
                                     [:named-key ?ag ?signer]]}
                             {:id   :delegated-naming
                              :head [:member ?group ?ak]
                              :body [[:block-signed-by ?idx ?signer]
                                     [:can-name ?group ?signer]
                                     [:named-key ?group ?ak]]}
                             {:id   :resolve-member
                              :head [:authenticated-as ?group]
                              :body [[:member ?group ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind  :allow
                                 :query [[:authenticated-as ?name]
                                         [:right ?name ?action ?r]]}]})]
      (t/is (not (:valid? result))))))

(t/deftest delegation-indirect-trust-via-group-membership
  (t/testing "Authority trusts naming by members of a meta-group"
    (let [root-kp  (sw/new-keypair)
          idp-a-kp (sw/new-keypair)
          idp-b-kp (sw/new-keypair)
          agent    (sw/new-keypair)
          idp-a-pk (crypto/encode-public-key (:pub idp-a-kp))
          idp-b-pk (crypto/encode-public-key (:pub idp-b-kp))
          agent-pk (crypto/encode-public-key (:pub agent))

          ;; Root: entitlements for "authorized-client"
          ;; Trust: anyone in "client-authorities" can name "authorized-client"
          ;; Members of "client-authorities": idp-a and idp-b
          token (sw/issue
                 {:facts [[:right "authorized-client" :read "/api/data"]
                          [:can-name-if-member "authorized-client" "client-authorities"]
                          [:named-key "client-authorities" idp-a-pk]
                          [:named-key "client-authorities" idp-b-pk]]}
                 {:private-key (:priv root-kp)})

          ;; IdP-B signs third-party block asserting agent membership
          tp-req (sw/third-party-request token)
          tp-block (sw/create-third-party-block
                     tp-req
                     {:facts [[:named-key "authorized-client" agent-pk]]}
                     {:private-key (:priv idp-b-kp) :public-key (:pub idp-b-kp)})
          token2 (sw/append-third-party token tp-block)

          signed (req/sign-request {:action :read} (:priv agent) (:pub agent))
          verified-key (req/verify-request signed)

          ;; Delegation chain:
          ;; 1. block-signed-by ?idx idp-b-pk
          ;; 2. named-key "client-authorities" idp-b-pk (from authority block)
          ;; 3. can-name-if-member "authorized-client" "client-authorities"
          ;; 4. → can-name "authorized-client" idp-b-pk (derived)
          ;; 5. named-key "authorized-client" agent-pk (from IdP-B's block)
          ;; 6. → member "authorized-client" agent-pk (derived)
          ;; 7. request-verified-agent-key agent-pk
          ;; 8. → authenticated-as "authorized-client" (derived)
          ;; 9. right "authorized-client" :read "/api/data" → allow
          result (sw/evaluate token2
                   :authorizer
                   {:trusted-external-keys [(:pub idp-b-kp)]
                    :facts [[:request-verified-agent-key verified-key]]
                    :rules '[;; Indirect trust: derive can-name from meta-group
                             {:id   :trust-chain
                              :head [:can-name ?target-group ?signer]
                              :body [[:can-name-if-member ?target-group ?auth-group]
                                     [:named-key ?auth-group ?signer]]}
                             ;; Delegated naming: accept named-key if signer is trusted
                             {:id   :delegated-naming
                              :head [:member ?group ?agent-key]
                              :body [[:block-signed-by ?idx ?signer]
                                     [:can-name ?group ?signer]
                                     [:named-key ?group ?agent-key]]}
                             ;; Resolve membership to authentication
                             {:id   :resolve-member
                              :head [:authenticated-as ?group]
                              :body [[:member ?group ?k]
                                     [:request-verified-agent-key ?k]]}]
                    :policies '[{:kind  :allow
                                 :query [[:authenticated-as ?name]
                                         [:right ?name ?action ?r]]}]})]
      (t/is (:valid? result)))))
