(ns stroopwafel.core-test
  (:require [stroopwafel.core :as sut]
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
                            :query [[:right "alice" :read "file-1"]]}]}
                 {:private-key (:priv kp)})

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
             {:facts [[:admin "alice"]]}
             {:private-key (:priv kp)})

            result (sut/evaluate token-with-admin
                                 :authorizer
                                 {:checks [{:id    :needs-admin
                                            :query [[:admin "alice"]]}]})]
        (t/is (false? (:valid? result)))))))

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
