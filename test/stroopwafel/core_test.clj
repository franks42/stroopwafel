(ns stroopwafel.core-test
  (:require [stroopwafel.core :as sut]
            [clojure.test :as t]))

(t/deftest end-to-end-with-authorizer
  (t/testing "Full round-trip: issue -> attenuate -> evaluate with authorizer"
    (let [;; Authority block with rights
          token {:blocks [{:facts  [[:right "alice" :read "file-1"]
                                    [:right "alice" :write "file-1"]]
                           :rules  '[{:id   :can-from-right
                                      :head [:can ?u ?a ?r]
                                      :body [[:right ?u ?a ?r]]}]
                           :checks []}
                          ;; Delegated block attenuates: only read access
                          {:facts  []
                           :rules  []
                           :checks [{:id    :read-only
                                     :query [[:right "alice" :read "file-1"]]}]}]}

          ;; Evaluate with authorizer context
          result (sut/evaluate token
                               :explain? true
                               :authorizer
                               {:facts  [[:time 1000]]
                                :checks [{:id    :check-read
                                          :query [[:can "alice" :read "file-1"]]}]})]
      (t/is (true? (:valid? result)))
      (t/is (some? (:explain result)))

      ;; Authorizer check that should fail (delegated block
      ;; cannot make admin fact visible to authorizer)
      (let [token-with-admin
            {:blocks (conj (:blocks token)
                           {:facts [[:admin "alice"]]
                            :rules []
                            :checks []})}

            result (sut/evaluate token-with-admin
                                 :authorizer
                                 {:checks [{:id    :needs-admin
                                            :query [[:admin "alice"]]}]})]
        (t/is (false? (:valid? result)))))))

(t/deftest authorizer-allow-policy
  (t/testing "Allow policy passes when query matches"
    (let [token {:blocks [{:facts [[:right "alice" :read "/data"]]
                           :rules []
                           :checks []}]}
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:right "alice" :read "/data"]]}]})]
      (t/is (true? (:valid? result))))))

(t/deftest authorizer-deny-policy
  (t/testing "Deny policy fails when query matches"
    (let [token {:blocks [{:facts [[:user "mallory"]]
                           :rules []
                           :checks []}]}
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :deny
                                            :query [[:user "mallory"]]}
                                           {:kind :allow
                                            :query [[:user "mallory"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-no-matching-policy-fails
  (t/testing "No matching policy results in deny (closed-world)"
    (let [token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}]}
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:admin "alice"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-policy-order-matters
  (t/testing "First matching policy wins - order determines outcome"
    (let [token {:blocks [{:facts [[:user "alice"] [:role "alice" :admin]]
                           :rules []
                           :checks []}]}
          ;; Allow first, deny second - allow wins
          result1 (sut/evaluate token
                                :authorizer
                                {:policies [{:kind :allow
                                             :query [[:role "alice" :admin]]}
                                            {:kind :deny
                                             :query [[:user "alice"]]}]})
          ;; Deny first, allow second - deny wins
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
    (let [token {:blocks [{:facts  [[:user "alice"]]
                           :rules  []
                           :checks [{:id :c1 :query [[:admin "alice"]]}]}]}
          ;; Policy would allow, but check fails first
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:user "alice"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-policies-see-only-authority
  (t/testing "Policies only see authority + authorizer facts, not delegated block facts"
    (let [token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}
                          {:facts [[:role "alice" :admin]]
                           :rules []
                           :checks []}]}
          ;; Policy queries delegated fact - should not match
          result (sut/evaluate token
                               :authorizer
                               {:policies [{:kind :allow
                                            :query [[:role "alice" :admin]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest evaluate-without-authorizer
  (t/testing "Existing calls without :authorizer still work"
    (let [token {:blocks [{:facts  [[:user "alice"]]
                           :rules  []
                           :checks [{:id :c1
                                     :query [[:user "alice"]]}]}]}
          result (sut/evaluate token :explain? true)]
      (t/is (true? (:valid? result)))
      (t/is (some? (:explain result))))))

(t/deftest multiple-blocks-scope-isolation
  (t/testing "Attenuate uses token's proof - multiple blocks with scope isolation"
    (let [token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}
                          {:facts []
                           :rules []
                           :checks [{:id :c1 :query [[:user "alice"]]}]}
                          {:facts []
                           :rules []
                           :checks [{:id :c2 :query [[:user "alice"]]}]}]}]
      (t/is (= 3 (count (:blocks token))))
      (t/is (true? (:valid? (sut/evaluate token)))))))

;;; ---- Datalog expressions end-to-end tests ----

(t/deftest e2e-time-expiry
  (t/testing "Token with time-based expiry check"
    (let [token {:blocks [{:facts  [[:right "alice" :read "/data"]]
                           :rules  []
                           :checks '[{:id    :check-expiry
                                      :query [[:time ?t]]
                                      :when  [(< ?t 2000000000000)]}]}]}
          ;; Time before expiry - should pass
          result-ok (sut/evaluate token
                                  :authorizer
                                  {:facts    [[:time 1000000000000]]
                                   :policies [{:kind :allow
                                               :query [[:right "alice" :read "/data"]]}]})
          ;; Time after expiry - should fail
          result-fail (sut/evaluate token
                                    :authorizer
                                    {:facts    [[:time 3000000000000]]
                                     :policies [{:kind :allow
                                                 :query [[:right "alice" :read "/data"]]}]})]
      (t/is (true? (:valid? result-ok)))
      (t/is (false? (:valid? result-fail))))))

(t/deftest e2e-amount-limit
  (t/testing "Amount limit via authorizer"
    (let [token {:blocks [{:facts  [[:user "alice"]]
                           :rules  []
                           :checks '[{:id    :max-transfer
                                      :query [[:transfer-amount ?a]]
                                      :when  [(<= ?a 10000)]}]}]}
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
    (let [token {:blocks [{:facts  [[:user "alice"]]
                           :rules  []
                           :checks '[{:id    :public-only
                                      :query [[:resource ?r]]
                                      :when  [(str/starts-with? ?r "/public/")]}]}]}
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
    (let [token {:blocks [{:facts [[:role "alice" :admin]]
                           :rules []
                           :checks []}]}
          ;; Amount within limit - policy allows
          result-ok (sut/evaluate token
                                  :authorizer
                                  {:facts    [[:amount 50]]
                                   :policies '[{:kind  :allow
                                                :query [[:role "alice" :admin] [:amount ?a]]
                                                :when  [(<= ?a 100)]}]})
          ;; Amount over limit - policy doesn't match - deny by default
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
  (t/testing "Third-party block with external-key: evaluate with trusted key"
    (let [idp-key (byte-array [1 2 3 4 5])

          token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}
                          {:facts [[:email "alice" "alice@idp.com"]]
                           :rules []
                           :checks []
                           :external-key idp-key}]}]

      (t/is (= 2 (count (:blocks token))))

      ;; Evaluate with trusted key
      (let [result (sut/evaluate token
                                 :authorizer
                                 {:trusted-external-keys [idp-key]
                                  :checks [{:id    :has-email
                                            :query [[:email "alice" "alice@idp.com"]]}]})]
        (t/is (true? (:valid? result))))

      ;; Without trusting the key, authorizer can't see third-party facts
      (let [result (sut/evaluate token
                                 :authorizer
                                 {:checks [{:id    :has-email
                                            :query [[:email "alice" "alice@idp.com"]]}]})]
        (t/is (false? (:valid? result)))))))

(t/deftest third-party-untrusted-key-rejected
  (t/testing "Third-party block with untrusted key is not visible"
    (let [idp-key   (byte-array [1 2 3 4 5])
          other-key (byte-array [9 8 7 6 5])

          token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}
                          {:facts [[:verified "alice"]]
                           :rules []
                           :checks []
                           :external-key idp-key}]}

          ;; Trust a different key - third-party facts not visible
          result (sut/evaluate token
                               :authorizer
                               {:trusted-external-keys [other-key]
                                :checks [{:id    :has-verified
                                          :query [[:verified "alice"]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest third-party-mixed-blocks
  (t/testing "Mixed first-party + third-party blocks"
    (let [idp-key (byte-array [10 20 30])

          token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}
                          ;; First-party attenuation
                          {:facts []
                           :rules []
                           :checks [{:id :c1 :query [[:user "alice"]]}]}
                          ;; Third-party block
                          {:facts [[:idp-verified "alice"]]
                           :rules []
                           :checks []
                           :external-key idp-key}
                          ;; Another first-party attenuation
                          {:facts []
                           :rules []
                           :checks [{:id :c2 :query [[:user "alice"]]}]}]}]

      (t/is (= 4 (count (:blocks token))))
      (t/is (true? (:valid? (sut/evaluate token
                                          :authorizer
                                          {:trusted-external-keys [idp-key]
                                           :checks [{:id    :has-idp
                                                     :query [[:idp-verified "alice"]]}]})))))))

(t/deftest third-party-multiple-trusted-keys
  (t/testing "Multiple trusted external keys"
    (let [idp-key-a (byte-array [1 2 3])
          idp-key-b (byte-array [4 5 6])

          token {:blocks [{:facts [[:user "alice"]]
                           :rules []
                           :checks []}
                          {:facts [[:email "alice" "a@idp-a.com"]]
                           :rules []
                           :checks []
                           :external-key idp-key-a}
                          {:facts [[:phone "alice" "+1234"]]
                           :rules []
                           :checks []
                           :external-key idp-key-b}]}

          result (sut/evaluate token
                               :authorizer
                               {:trusted-external-keys [idp-key-a idp-key-b]
                                :checks [{:id    :has-both
                                          :query [[:email "alice" "a@idp-a.com"]
                                                  [:phone "alice" "+1234"]]}]})]
      (t/is (true? (:valid? result))))))
