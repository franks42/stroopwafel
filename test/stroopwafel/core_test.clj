(ns stroopwafel.core-test
  (:require [stroopwafel.core :as sut]
            [stroopwafel.crypto :as crypto]
            [clojure.test :as t]))

(t/deftest end-to-end-with-authorizer
  (t/testing "Full round-trip: issue → attenuate → verify → evaluate with authorizer"
    (let [kp (sut/new-keypair)

          ;; Authority issues token with rights
          token (sut/issue
                 {:facts  [[:right "alice" :read "file-1"]
                           [:right "alice" :write "file-1"]]
                  :rules  '[{:id   :can-from-right
                             :head [:can ?u ?a ?r]
                             :body [[:right ?u ?a ?r]]}]}
                 {:private-key (:priv kp)})

          ;; Delegated block attenuates: only read access
          token (sut/attenuate
                 token
                 {:checks [{:id    :read-only
                            :query [[:right "alice" :read "file-1"]]}]})

          ;; Verify chain integrity
          verified? (sut/verify token {:public-key (:pub kp)})]

      (t/is (true? verified?))

      ;; Evaluate with authorizer context
      (let [result (sut/evaluate token
                                 :explain? true
                                 :authorizer
                                 {:facts  [[:time 1000]]
                                  :checks [{:id    :check-read
                                            :query [[:can "alice" :read "file-1"]]}]})]
        (t/is (true? (:valid? result)))
        (t/is (some? (:explain result))))

      ;; Authorizer check that should fail (delegated block
      ;; cannot make admin fact visible to authorizer)
      (let [token-with-admin
            (sut/attenuate
             token
             {:facts [[:admin "alice"]]})

            result (sut/evaluate token-with-admin
                                 :authorizer
                                 {:checks [{:id    :needs-admin
                                            :query [[:admin "alice"]]}]})]
        (t/is (false? (:valid? result)))))))

(t/deftest revocation-ids-unique-per-block
  (t/testing "Each block produces a unique revocation ID"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          token (sut/attenuate
                 token
                 {:checks [{:id :c1 :query [[:user "alice"]]}]})
          ids (sut/revocation-ids token)]
      (t/is (= 2 (count ids)))
      (t/is (not= (first ids) (second ids))))))

(t/deftest revocation-ids-stable
  (t/testing "Same token always produces the same revocation IDs"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          ids1 (sut/revocation-ids token)
          ids2 (sut/revocation-ids token)]
      (t/is (= ids1 ids2)))))

(t/deftest revocation-ids-grow-on-attenuate
  (t/testing "Attenuating appends a new revocation ID, preserving existing ones"
    (let [kp (sut/new-keypair)
          token1 (sut/issue
                  {:facts [[:user "alice"]]}
                  {:private-key (:priv kp)})
          ids1 (sut/revocation-ids token1)
          token2 (sut/attenuate
                  token1
                  {:checks [{:id :c1 :query [[:user "alice"]]}]})
          ids2 (sut/revocation-ids token2)]
      (t/is (= 1 (count ids1)))
      (t/is (= 2 (count ids2)))
      ;; First ID is preserved
      (t/is (= (first ids1) (first ids2))))))

(t/deftest revocation-ids-are-hex-strings
  (t/testing "Revocation IDs are 64-char lowercase hex strings (SHA-256)"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          ids (sut/revocation-ids token)]
      (t/is (= 1 (count ids)))
      (t/is (= 64 (count (first ids))))
      (t/is (re-matches #"[0-9a-f]{64}" (first ids))))))

(t/deftest authorizer-allow-policy
  (t/testing "Allow policy passes when query matches"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:right "alice" :read "/data"]]}
                 {:private-key (:priv kp)})
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:right "alice" :read "/data"]]}]})]
      (t/is (true? (:valid? result))))))

(t/deftest authorizer-deny-policy
  (t/testing "Deny policy fails when query matches"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "mallory"]]}
                 {:private-key (:priv kp)})
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :deny
                                            :query [[:user "mallory"]]}
                                           {:kind :allow
                                            :query [[:user "mallory"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-no-matching-policy-fails
  (t/testing "No matching policy results in deny (closed-world)"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:admin "alice"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-policy-order-matters
  (t/testing "First matching policy wins — order determines outcome"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"] [:role "alice" :admin]]}
                 {:private-key (:priv kp)})
          ;; Allow first, deny second — allow wins
          result1 (sut/evaluate token
                                :authorizer
                                {:policies [{:kind :allow
                                             :query [[:role "alice" :admin]]}
                                            {:kind :deny
                                             :query [[:user "alice"]]}]})
          ;; Deny first, allow second — deny wins
          result2 (sut/evaluate token
                                :authorizer
                                {:policies [{:kind :deny
                                             :query [[:user "alice"]]}
                                            {:kind :allow
                                             :query [[:role "alice" :admin]]}]})]
      (t/is (true? (:valid? result1)))
      (t/is (false? (:valid? result2))))))

(t/deftest authorizer-policies-with-checks
  (t/testing "Checks must pass before policies are evaluated"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts  [[:user "alice"]]
                  :checks [{:id :c1 :query [[:admin "alice"]]}]}
                 {:private-key (:priv kp)})
          ;; Policy would allow, but check fails first
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:user "alice"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-policies-see-only-authority
  (t/testing "Policies only see authority + authorizer facts, not delegated block facts"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          token (sut/attenuate
                 token
                 {:facts [[:role "alice" :admin]]})
          ;; Policy queries delegated fact — should not match
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:role "alice" :admin]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest evaluate-backward-compatible
  (t/testing "Existing calls without :authorizer still work"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts  [[:user "alice"]]
                  :checks [{:id :c1
                            :query [[:user "alice"]]}]}
                 {:private-key (:priv kp)})
          result (sut/evaluate token :explain? true)]
      (t/is (true? (:valid? result)))
      (t/is (some? (:explain result))))))

(t/deftest ephemeral-key-attenuate-no-explicit-key
  (t/testing "Attenuate uses token's proof — no explicit key needed"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          ;; Attenuate without providing any key
          token2 (sut/attenuate token {:checks [{:id :c1 :query [[:user "alice"]]}]})
          token3 (sut/attenuate token2 {:checks [{:id :c2 :query [[:user "alice"]]}]})]
      (t/is (= 3 (count (:blocks token3))))
      (t/is (true? (sut/verify token3 {:public-key (:pub kp)}))))))

(t/deftest token-contains-proof
  (t/testing "Token contains ephemeral private key as proof"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})]
      (t/is (some? (:proof token)))
      (t/is (crypto/ed25519-private-key? (:proof token))))))

(t/deftest sealed-token-verifies
  (t/testing "Sealed token passes verification"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          sealed (sut/seal token)]
      (t/is (true? (sut/sealed? sealed)))
      (t/is (true? (sut/verify sealed {:public-key (:pub kp)}))))))

(t/deftest sealed-token-rejects-attenuate
  (t/testing "Cannot attenuate a sealed token"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          sealed (sut/seal token)]
      (t/is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"Cannot attenuate a sealed token"
                              (sut/attenuate sealed {:checks [{:id :c1 :query [[:user "alice"]]}]}))))))

(t/deftest sealed-token-evaluates
  (t/testing "Sealed token evaluates the same as unsealed"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts  [[:user "alice"]]
                  :checks [{:id :c1 :query [[:user "alice"]]}]}
                 {:private-key (:priv kp)})
          sealed (sut/seal token)
          r1 (sut/evaluate token)
          r2 (sut/evaluate sealed)]
      (t/is (= (:valid? r1) (:valid? r2) true)))))

(t/deftest double-seal-rejected
  (t/testing "Cannot seal an already sealed token"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv kp)})
          sealed (sut/seal token)]
      (t/is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"already sealed"
                              (sut/seal sealed))))))

(t/deftest sealed-token-with-attenuation
  (t/testing "Attenuate then seal — full chain verifies"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:right "alice" :read "/data"]]}
                 {:private-key (:priv kp)})
          token (sut/attenuate token {:checks [{:id :c1 :query [[:right "alice" :read "/data"]]}]})
          sealed (sut/seal token)]
      (t/is (= 2 (count (:blocks sealed))))
      (t/is (true? (sut/verify sealed {:public-key (:pub kp)})))
      (t/is (true? (:valid? (sut/evaluate sealed)))))))

;;; ---- Datalog expressions end-to-end tests ----

(t/deftest e2e-time-expiry
  (t/testing "Token with time-based expiry check"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts  [[:right "alice" :read "/data"]]
                  :checks '[{:id    :check-expiry
                             :query [[:time ?t]]
                             :when  [(< ?t 2000000000000)]}]}
                 {:private-key (:priv kp)})
          ;; Time before expiry — should pass
          result-ok (sut/evaluate token
                                  :authorizer
                                  {:facts    [[:time 1000000000000]]
                                   :policies [{:kind :allow
                                               :query [[:right "alice" :read "/data"]]}]})
          ;; Time after expiry — should fail
          result-fail (sut/evaluate token
                                    :authorizer
                                    {:facts    [[:time 3000000000000]]
                                     :policies [{:kind :allow
                                                 :query [[:right "alice" :read "/data"]]}]})]
      (t/is (true? (:valid? result-ok)))
      (t/is (false? (:valid? result-fail))))))

(t/deftest e2e-amount-limit
  (t/testing "Amount limit via authorizer"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts  [[:user "alice"]]
                  :checks '[{:id    :max-transfer
                             :query [[:transfer-amount ?a]]
                             :when  [(<= ?a 10000)]}]}
                 {:private-key (:priv kp)})
          result-ok (sut/evaluate token
                                  :authorizer
                                  {:facts [[:transfer-amount 5000]]})
          result-fail (sut/evaluate token
                                    :authorizer
                                    {:facts [[:transfer-amount 50000]]})]
      (t/is (true? (:valid? result-ok)))
      (t/is (false? (:valid? result-fail))))))

(t/deftest e2e-string-prefix
  (t/testing "String prefix check on resource path"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts  [[:user "alice"]]
                  :checks '[{:id    :public-only
                             :query [[:resource ?r]]
                             :when  [(str/starts-with? ?r "/public/")]}]}
                 {:private-key (:priv kp)})
          result-ok (sut/evaluate token
                                  :authorizer
                                  {:facts [[:resource "/public/docs"]]})
          result-fail (sut/evaluate token
                                    :authorizer
                                    {:facts [[:resource "/private/secrets"]]})]
      (t/is (true? (:valid? result-ok)))
      (t/is (false? (:valid? result-fail))))))

(t/deftest e2e-policy-with-guard
  (t/testing "Policy with :when guard"
    (let [kp (sut/new-keypair)
          token (sut/issue
                 {:facts [[:role "alice" :admin]]}
                 {:private-key (:priv kp)})
          ;; Amount within limit — policy allows
          result-ok (sut/evaluate token
                                  :authorizer
                                  {:facts    [[:amount 50]]
                                   :policies '[{:kind  :allow
                                                :query [[:role "alice" :admin] [:amount ?a]]
                                                :when  [(<= ?a 100)]}]})
          ;; Amount over limit — policy doesn't match — deny by default
          result-fail (sut/evaluate token
                                    :authorizer
                                    {:facts    [[:amount 200]]
                                     :policies '[{:kind  :allow
                                                  :query [[:role "alice" :admin] [:amount ?a]]
                                                  :when  [(<= ?a 100)]}]})]
      (t/is (true? (:valid? result-ok)))
      (t/is (false? (:valid? result-fail))))))

;;; ---- Third-party block end-to-end tests ----

(t/deftest third-party-full-flow
  (t/testing "Full flow: issue → request → third-party sign → append → verify → evaluate"
    (let [root-kp (sut/new-keypair)
          idp-kp  (sut/new-keypair)

          ;; 1. Issue token
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv root-kp)})

          ;; 2. Token holder creates request
          request (sut/third-party-request token)

          ;; 3. Third party signs block
          tp-block (sut/create-third-party-block
                    request
                    {:facts [[:email "alice" "alice@idp.com"]]}
                    {:private-key (:priv idp-kp)
                     :public-key  (:pub idp-kp)})

          ;; 4. Token holder appends
          token (sut/append-third-party token tp-block)

          ;; 5. Verify
          verified? (sut/verify token {:public-key (:pub root-kp)})]

      (t/is (true? verified?))
      (t/is (= 2 (count (:blocks token))))

      ;; 6. Evaluate with trusted key
      (let [result (sut/evaluate token
                                 :authorizer
                                 {:trusted-external-keys [(:pub idp-kp)]
                                  :checks [{:id    :has-email
                                            :query [[:email "alice" "alice@idp.com"]]}]})]
        (t/is (true? (:valid? result))))

      ;; Without trusting the key, authorizer can't see third-party facts
      (let [result (sut/evaluate token
                                 :authorizer
                                 {:checks [{:id    :has-email
                                            :query [[:email "alice" "alice@idp.com"]]}]})]
        (t/is (false? (:valid? result)))))))

(t/deftest third-party-replay-prevention
  (t/testing "Block signed for token A fails verification on token B"
    (let [root-kp (sut/new-keypair)
          idp-kp  (sut/new-keypair)

          token-a (sut/issue
                   {:facts [[:user "alice"]]}
                   {:private-key (:priv root-kp)})
          token-b (sut/issue
                   {:facts [[:user "bob"]]}
                   {:private-key (:priv root-kp)})

          ;; Create request for token A
          request-a (sut/third-party-request token-a)

          ;; Third party signs for token A
          tp-block (sut/create-third-party-block
                    request-a
                    {:facts [[:verified "alice"]]}
                    {:private-key (:priv idp-kp)
                     :public-key  (:pub idp-kp)})

          ;; Try to append to token B (different previous-sig)
          token-b-with-tp (sut/append-third-party token-b tp-block)

          ;; Verification should fail (external sig bound to token A's previous sig)
          verified? (sut/verify token-b-with-tp {:public-key (:pub root-kp)})]

      (t/is (false? verified?)))))

(t/deftest third-party-sealed-token-rejects
  (t/testing "Sealed token rejects third-party request and append"
    (let [root-kp (sut/new-keypair)
          idp-kp  (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv root-kp)})

          ;; Get request before sealing
          request (sut/third-party-request token)
          tp-block (sut/create-third-party-block
                    request
                    {:facts [[:verified "alice"]]}
                    {:private-key (:priv idp-kp)
                     :public-key  (:pub idp-kp)})

          sealed (sut/seal token)]

      (t/is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"sealed"
                              (sut/third-party-request sealed)))
      (t/is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"sealed"
                              (sut/append-third-party sealed tp-block))))))

(t/deftest third-party-mixed-blocks
  (t/testing "Mixed first-party + third-party blocks"
    (let [root-kp (sut/new-keypair)
          idp-kp  (sut/new-keypair)

          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv root-kp)})

          ;; First-party attenuation
          token (sut/attenuate token
                               {:checks [{:id :c1 :query [[:user "alice"]]}]})

          ;; Third-party block
          request (sut/third-party-request token)
          tp-block (sut/create-third-party-block
                    request
                    {:facts [[:idp-verified "alice"]]}
                    {:private-key (:priv idp-kp)
                     :public-key  (:pub idp-kp)})
          token (sut/append-third-party token tp-block)

          ;; Another first-party attenuation
          token (sut/attenuate token
                               {:checks [{:id :c2 :query [[:user "alice"]]}]})]

      (t/is (= 4 (count (:blocks token))))
      (t/is (true? (sut/verify token {:public-key (:pub root-kp)})))
      (t/is (true? (:valid? (sut/evaluate token
                                          :authorizer
                                          {:trusted-external-keys [(:pub idp-kp)]
                                           :checks [{:id    :has-idp
                                                     :query [[:idp-verified "alice"]]}]})))))))

(t/deftest third-party-revocation-ids
  (t/testing "Revocation IDs include third-party blocks"
    (let [root-kp (sut/new-keypair)
          idp-kp  (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv root-kp)})
          request (sut/third-party-request token)
          tp-block (sut/create-third-party-block
                    request
                    {:facts [[:verified "alice"]]}
                    {:private-key (:priv idp-kp)
                     :public-key  (:pub idp-kp)})
          token (sut/append-third-party token tp-block)
          ids (sut/revocation-ids token)]
      (t/is (= 2 (count ids)))
      (t/is (not= (first ids) (second ids)))
      (t/is (every? #(re-matches #"[0-9a-f]{64}" %) ids)))))

(t/deftest third-party-seal-after-append
  (t/testing "Seal after third-party append works correctly"
    (let [root-kp (sut/new-keypair)
          idp-kp  (sut/new-keypair)
          token (sut/issue
                 {:facts [[:user "alice"]]}
                 {:private-key (:priv root-kp)})
          request (sut/third-party-request token)
          tp-block (sut/create-third-party-block
                    request
                    {:facts [[:verified "alice"]]}
                    {:private-key (:priv idp-kp)
                     :public-key  (:pub idp-kp)})
          token (sut/append-third-party token tp-block)
          sealed (sut/seal token)]
      (t/is (true? (sut/sealed? sealed)))
      (t/is (true? (sut/verify sealed {:public-key (:pub root-kp)})))
      (t/is (true? (:valid? (sut/evaluate sealed
                                          :authorizer
                                          {:trusted-external-keys [(:pub idp-kp)]
                                           :checks [{:id    :c1
                                                     :query [[:verified "alice"]]}]})))))))
