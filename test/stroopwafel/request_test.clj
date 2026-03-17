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
