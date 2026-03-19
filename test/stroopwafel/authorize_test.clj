(ns stroopwafel.authorize-test
  (:require [stroopwafel.authorize :as auth]
            [stroopwafel.core :as sw]
            [stroopwafel.crypto :as crypto]
            [stroopwafel.request :as req]
            [clojure.test :as t]))

;; --- Basic context operations ---

(t/deftest empty-context-no-policy
  (t/testing "Empty context with no policy defaults to valid"
    (let [result (auth/authorize (auth/context))]
      (t/is (:allowed? result)))))

(t/deftest single-token-allow
  (t/testing "Single token with matching policy allows"
    (let [root-kp (sw/new-keypair)
          token   (sw/issue {:facts [[:right "alice" :read "/data"]]}
                            {:private-key (:priv root-kp) :public-key (:pub root-kp)})
          result  (-> (auth/context)
                      (auth/add-token token {:public-key (:pub root-kp)})
                      (auth/authorize
                        :policies '[{:kind :allow
                                     :query [[:right "alice" :read ?r]]}]))]
      (t/is (:allowed? result)))))

(t/deftest invalid-token-rejected
  (t/testing "Token with wrong public key fails verification"
    (let [root-kp  (sw/new-keypair)
          wrong-kp (sw/new-keypair)
          token    (sw/issue {:facts [[:x 1]]}
                             {:private-key (:priv root-kp) :public-key (:pub root-kp)})
          result   (-> (auth/context)
                       (auth/add-token token {:public-key (:pub wrong-kp)})
                       (auth/authorize
                         :policies '[{:kind :allow :query [[:x 1]]}]))]
      (t/is (not (:allowed? result)))
      (t/is (seq (:errors result))))))

;; --- Multi-token composition ---

(t/deftest two-tokens-combined
  (t/testing "Facts from two independently signed tokens are combined"
    (let [idp-kp     (sw/new-keypair)
          service-kp (sw/new-keypair)

          ;; IdP issues name certificate
          name-cert (sw/issue
                      {:facts [[:named-key "ops-team" (byte-array [1 2 3])]]}
                      {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})

          ;; Service issues capability
          capability (sw/issue
                       {:facts [[:right "ops-team" :read "/metrics"]]}
                       {:private-key (:priv service-kp) :public-key (:pub service-kp)})

          result (-> (auth/context)
                     (auth/add-token name-cert {:public-key (:pub idp-kp)})
                     (auth/add-token capability {:public-key (:pub service-kp)})
                     (auth/authorize
                       :policies '[{:kind :allow
                                    :query [[:right "ops-team" :read ?r]
                                            [:named-key "ops-team" ?k]]}]))]
      (t/is (:allowed? result)))))

(t/deftest two-tokens-one-invalid
  (t/testing "One invalid token poisons the entire context"
    (let [good-kp  (sw/new-keypair)
          bad-kp   (sw/new-keypair)
          wrong-kp (sw/new-keypair)

          good-token (sw/issue {:facts [[:x 1]]}
                               {:private-key (:priv good-kp) :public-key (:pub good-kp)})
          bad-token  (sw/issue {:facts [[:y 2]]}
                               {:private-key (:priv bad-kp) :public-key (:pub bad-kp)})

          result (-> (auth/context)
                     (auth/add-token good-token {:public-key (:pub good-kp)})
                     (auth/add-token bad-token {:public-key (:pub wrong-kp)})
                     (auth/authorize
                       :policies '[{:kind :allow :query [[:x 1]]}]))]
      (t/is (not (:allowed? result)))
      (t/is (= 1 (count (:errors result)))))))

;; --- Signed request integration ---

(t/deftest signed-request-with-multi-token
  (t/testing "Full SPKI/SDSI flow: name cert + capability + signed request"
    (let [idp-kp     (sw/new-keypair)
          service-kp (sw/new-keypair)
          agent-kp   (sw/new-keypair)
          agent-pk   (crypto/encode-public-key (:pub agent-kp))

          ;; IdP: this agent is in ops-team
          name-cert (sw/issue
                      {:facts [[:named-key "ops-team" agent-pk]]}
                      {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})

          ;; Service: ops-team can read metrics
          capability (sw/issue
                       {:facts [[:right "ops-team" :read "/metrics"]]}
                       {:private-key (:priv service-kp) :public-key (:pub service-kp)})

          ;; Agent signs request
          signed (req/sign-request {:action :read :path "/metrics"}
                                   (:priv agent-kp) (:pub agent-kp))

          result (-> (auth/context)
                     (auth/add-token name-cert {:public-key (:pub idp-kp)})
                     (auth/add-token capability {:public-key (:pub service-kp)})
                     (auth/add-signed-request signed)
                     (auth/add-facts [[:time (System/currentTimeMillis)]])
                     (auth/authorize
                       :rules '[{:id   :resolve-name
                                 :head [:authenticated-as ?name]
                                 :body [[:named-key ?name ?k]
                                        [:request-verified-agent-key ?k]]}]
                       :policies '[{:kind  :allow
                                    :query [[:authenticated-as ?name]
                                            [:right ?name :read ?r]]}]))]
      (t/is (:allowed? result)))))

(t/deftest signed-request-wrong-agent
  (t/testing "Agent not in named group is rejected"
    (let [idp-kp     (sw/new-keypair)
          service-kp (sw/new-keypair)
          member-kp  (sw/new-keypair)
          outsider-kp (sw/new-keypair)
          member-pk  (crypto/encode-public-key (:pub member-kp))

          name-cert (sw/issue
                      {:facts [[:named-key "ops-team" member-pk]]}
                      {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})

          capability (sw/issue
                       {:facts [[:right "ops-team" :read "/metrics"]]}
                       {:private-key (:priv service-kp) :public-key (:pub service-kp)})

          ;; Outsider signs
          signed (req/sign-request {:action :read}
                                   (:priv outsider-kp) (:pub outsider-kp))

          result (-> (auth/context)
                     (auth/add-token name-cert {:public-key (:pub idp-kp)})
                     (auth/add-token capability {:public-key (:pub service-kp)})
                     (auth/add-signed-request signed)
                     (auth/authorize
                       :rules '[{:id   :resolve-name
                                 :head [:authenticated-as ?name]
                                 :body [[:named-key ?name ?k]
                                        [:request-verified-agent-key ?k]]}]
                       :policies '[{:kind  :allow
                                    :query [[:authenticated-as ?name]
                                            [:right ?name :read ?r]]}]))]
      (t/is (not (:allowed? result))))))

(t/deftest invalid-signed-request
  (t/testing "Tampered request signature causes rejection"
    (let [root-kp  (sw/new-keypair)
          agent-kp (sw/new-keypair)

          token (sw/issue {:facts [[:x 1]]}
                          {:private-key (:priv root-kp) :public-key (:pub root-kp)})

          signed (req/sign-request {:action :read}
                                   (:priv agent-kp) (:pub agent-kp))
          tampered (assoc signed :body {:action :write})

          result (-> (auth/context)
                     (auth/add-token token {:public-key (:pub root-kp)})
                     (auth/add-signed-request tampered)
                     (auth/authorize
                       :policies '[{:kind :allow :query [[:x 1]]}]))]
      (t/is (not (:allowed? result)))
      (t/is (= :invalid-request-signature
               (-> result :errors first :reason))))))

;; --- Token checks enforced across context ---

(t/deftest token-checks-enforced
  (t/testing "Checks from added tokens are enforced during authorize"
    (let [root-kp (sw/new-keypair)
          token   (sw/issue
                    {:facts  [[:right :read "/data"]]
                     :checks '[{:id    :needs-time
                                :query [[:time ?t]]}]}
                    {:private-key (:priv root-kp) :public-key (:pub root-kp)})

          ;; Without providing time fact, check fails
          result-no-time
          (-> (auth/context)
              (auth/add-token token {:public-key (:pub root-kp)})
              (auth/authorize
                :policies '[{:kind :allow :query [[:right :read ?r]]}]))

          ;; With time fact, check passes
          result-with-time
          (-> (auth/context)
              (auth/add-token token {:public-key (:pub root-kp)})
              (auth/add-facts [[:time (System/currentTimeMillis)]])
              (auth/authorize
                :policies '[{:kind :allow :query [[:right :read ?r]]}]))]
      (t/is (not (:allowed? result-no-time)))
      (t/is (:allowed? result-with-time)))))

;; --- Three-token composition ---

(t/deftest three-tokens-composed
  (t/testing "Three tokens from three authorities compose correctly"
    (let [idp-kp      (sw/new-keypair)
          service-kp  (sw/new-keypair)
          limits-kp   (sw/new-keypair)
          agent-kp    (sw/new-keypair)
          agent-pk    (crypto/encode-public-key (:pub agent-kp))

          ;; IdP: agent identity
          name-cert (sw/issue
                      {:facts [[:named-key "traders" agent-pk]]}
                      {:private-key (:priv idp-kp) :public-key (:pub idp-kp)})

          ;; Service: what traders can do
          capability (sw/issue
                       {:facts [[:right "traders" :trade "/api/orders"]]}
                       {:private-key (:priv service-kp) :public-key (:pub service-kp)})

          ;; Risk: trading limits
          limits (sw/issue
                   {:facts [[:limit "traders" :max-amount 10000]]}
                   {:private-key (:priv limits-kp) :public-key (:pub limits-kp)})

          signed (req/sign-request {:action :trade :amount 5000}
                                   (:priv agent-kp) (:pub agent-kp))

          result (-> (auth/context)
                     (auth/add-token name-cert {:public-key (:pub idp-kp)})
                     (auth/add-token capability {:public-key (:pub service-kp)})
                     (auth/add-token limits {:public-key (:pub limits-kp)})
                     (auth/add-signed-request signed)
                     (auth/add-facts [[:request-amount 5000]])
                     (auth/authorize
                       :rules '[{:id   :resolve-name
                                 :head [:authenticated-as ?name]
                                 :body [[:named-key ?name ?k]
                                        [:request-verified-agent-key ?k]]}]
                       :policies '[{:kind  :allow
                                    :query [[:authenticated-as ?name]
                                            [:right ?name :trade ?r]
                                            [:limit ?name :max-amount ?max]
                                            [:request-amount ?amt]]
                                    :when  [(<= ?amt ?max)]}]))]
      (t/is (:allowed? result)))))
