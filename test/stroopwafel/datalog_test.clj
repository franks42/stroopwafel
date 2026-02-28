(ns stroopwafel.datalog-test
  (:require [stroopwafel.datalog :as sut]
            [clojure.test :as t]))

(t/deftest variable?-test
  (t/is (true?  (sut/variable? '?u)))
  (t/is (false? (sut/variable? :read)))
  (t/is (false? (sut/variable? "alice"))))

(t/deftest bind-test

  (t/testing "If the variable is unbound, associates it with the given value"
    (t/is (= '{?u "alice"}
             (sut/bind {} '?u "alice"))))

  (t/testing " If the variable is already bound, ensures the existing binding
  matches the value"
    (t/is (= '{?u "alice"}
             (sut/bind '{?u "alice"} '?u "alice"))))

  (t/testing "return nil if the binding would cause a conflict"
    (t/is (nil?
           (sut/bind '{?u "alice"} '?u "bob")))))

(t/deftest unify-test
  (t/testing "unify a pattern with a concrete fact"
    (let [result (sut/unify
                  '[:right ?u ?a ?r]
                  [:right "alice" :read "file-1"])]

      (t/is (= '{?u "alice" ?a :read ?r "file-1"}
               (:env result)))
      (t/is (= 1 (count (:proof result))))))

  (t/testing "if unification fails return nil"
    (t/is (nil?
           (sut/unify
            '[:right ?u ?a ?r]
            [:user "alice"])))))

(t/deftest eval-body-test
  (let [facts [[:right "alice" :read "file-1"]
               [:resource "file-1"]]
        body  '[[:right ?u ?a ?r]
                [:resource ?r]]
        results (sut/eval-body body facts)]
    (t/is (= 1 (count results)))
    (t/is (= '{?u "alice" ?a :read ?r "file-1"}
             (:env (first results))))
    (t/is (= 2 (count (:proof (first results)))))))

(t/deftest instantiate-test
  (t/is (= [:can "alice" :read "file-1"]
           (sut/instantiate
            '[:can ?u ?a ?r]
            '{?u "alice" ?a :read ?r "file-1"})))

  (t/is (nil?
         (sut/instantiate
          '[:can ?u ?r]
          '{?u "alice"}))))

(t/deftest fire-rule-test
  (let [facts [[:right "alice" :read "file-1"]]
        rule  '{:id   :can-from-right
                :head [:can ?u ?a ?r]
                :body [[:right ?u ?a ?r]]}
        results (sut/fire-rule rule facts)]
    (t/is (= 1 (count results)))
    (t/is (= [:can "alice" :read "file-1"]
             (:fact (first results))))
    (t/is (= :can-from-right
             (:rule (first results))))))

(t/deftest eval-check-pass-test
  (let [fact-store
        {[:can "alice" :read "file-1"] #{0}}
        check {:id :c1
               :query [[:can "alice" :read "file-1"]]}
        result (sut/eval-check check fact-store)]
    (t/is (= :pass (:result result)))))

(t/deftest eval-check-fail-test
  (let [check {:id :c1
               :query [[:can "alice" :write "file-1"]]}
        result (sut/eval-check check {})]
    (t/is (= :fail (:result result)))))

(t/deftest eval-token-valid-with-explain
  (let [token {:blocks
               [{:facts  [[:right "alice" :read "file-1"]]
                 :rules  '[{:id   :can-from-right
                            :head [:can ?u ?a ?r]
                            :body [[:right ?u ?a ?r]]}]
                 :checks [{:id :c1
                           :query [[:can "alice" :read "file-1"]]}]}]}
        result (sut/eval-token token :explain? true)]
    (t/is (true? (:valid? result)))
    (t/is (some? (:explain result)))))

(t/deftest eval-token-invalid
  (let [token {:blocks
               [{:facts  []
                 :rules  []
                 :checks [{:id :c1
                           :query [[:can "alice" :read "file-1"]]}]}]}
        result (sut/eval-token token :explain? true)]
    (t/is (false? (:valid? result)))
    (t/is (= :fail (get-in result [:explain :result])))))

;;; ---- Scoping tests (ported from Biscuit model) ----

(t/deftest scoped-rules-test
  (t/testing "Rule in block 1 can't see block 2's facts"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  []
                   :rules  '[{:id   :derive-admin
                              :head [:is-admin ?u]
                              :body [[:user ?u] [:role ?u :admin]]}]
                   :checks [{:id    :c1
                             :query [[:is-admin "alice"]]}]}
                  {:facts  [[:role "alice" :admin]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token)]
      (t/is (false? (:valid? result))))))

(t/deftest scoped-checks-test
  (t/testing "Check in block 1 can't see block 2's facts"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  []
                   :rules  []
                   :checks [{:id    :c1
                             :query [[:secret "data"]]}]}
                  {:facts  [[:secret "data"]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token)]
      (t/is (false? (:valid? result))))))

(t/deftest authorizer-scope-test
  (t/testing "Authorizer can't see delegated block facts"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:role "alice" :admin]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:checks [{:id    :c1
                                            :query [[:role "alice" :admin]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest execution-scope-test
  (t/testing "Block 2 can't see block 1's facts (only block 0 + own)"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:tag "block-1-data"]]
                   :rules  []
                   :checks []}
                  {:facts  []
                   :rules  []
                   :checks [{:id    :c1
                             :query [[:tag "block-1-data"]]}]}]}
          result (sut/eval-token token)]
      (t/is (false? (:valid? result))))))

(t/deftest derived-fact-origin-test
  (t/testing "Rule in block 1 derives fact with origin containing 1, invisible to block 0"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks [{:id    :c1
                             :query [[:derived-fact "alice"]]}]}
                  {:facts  []
                   :rules  '[{:id   :derive
                              :head [:derived-fact ?u]
                              :body [[:user ?u]]}]
                   :checks []}]}
          result (sut/eval-token token)]
      (t/is (false? (:valid? result))))))

(t/deftest reject-if-test
  (t/testing "Deny semantics: reject-if match = fail, no match = pass"
    (let [store {[:admin "mallory"] #{0}}
          ;; reject-if matches -> fail
          check-reject {:id :deny-admin :kind :reject
                        :query [[:admin "mallory"]]}
          ;; reject-if doesn't match -> pass
          check-reject-ok {:id :deny-admin :kind :reject
                           :query [[:admin "nobody"]]}]
      (t/is (= :fail (:result (sut/eval-check check-reject store))))
      (t/is (= :pass (:result (sut/eval-check check-reject-ok store)))))))

(t/deftest delegated-cannot-expand-authority-test
  (t/testing "Block 1 adds admin fact, block 0's check can't see it"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks [{:id    :c1
                             :query [[:admin "alice"]]}]}
                  {:facts  [[:admin "alice"]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token)]
      (t/is (false? (:valid? result))))))

(t/deftest attenuation-chain-test
  (t/testing "3-block progressive restriction, all checks pass"
    (let [token {:blocks
                 [{:facts  [[:right "alice" :read "file-1"]
                            [:right "alice" :write "file-1"]]
                   :rules  []
                   :checks []}
                  {:facts  []
                   :rules  []
                   :checks [{:id    :c1
                             :query [[:right "alice" :read "file-1"]]}]}
                  {:facts  []
                   :rules  []
                   :checks [{:id    :c2
                             :query [[:right "alice" :read "file-1"]]}]}]}
          result (sut/eval-token token)]
      (t/is (true? (:valid? result))))))

(t/deftest derived-fact-cross-block-test
  (t/testing "Derived fact from block 1 visible to block 1 but not block 2"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  []
                   :rules  '[{:id   :tag-user
                              :head [:tagged ?u]
                              :body [[:user ?u]]}]
                   :checks [{:id    :c1
                             :query [[:tagged "alice"]]}]}
                  {:facts  []
                   :rules  []
                   :checks [{:id    :c2
                             :query [[:tagged "alice"]]}]}]}
          result (sut/eval-token token)]
      (t/is (false? (:valid? result))))))
