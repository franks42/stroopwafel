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

;;; ---- Expression evaluator tests ----

(t/deftest eval-expr-literal-test
  (t/testing "Literals pass through unchanged"
    (t/is (= 42 (sut/eval-expr 42 {})))
    (t/is (= "hello" (sut/eval-expr "hello" {})))
    (t/is (= :kw (sut/eval-expr :kw {})))))

(t/deftest eval-expr-variable-test
  (t/testing "Variables are looked up in env"
    (t/is (= 500 (sut/eval-expr '?t '{?t 500}))))
  (t/testing "Unbound variable throws"
    (t/is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Unbound variable"
                            (sut/eval-expr '?x '{?t 500})))))

(t/deftest eval-expr-comparison-test
  (t/testing "Comparison operators"
    (t/is (true? (sut/eval-expr '(< ?t ?limit) '{?t 500 ?limit 1000})))
    (t/is (false? (sut/eval-expr '(> ?t ?limit) '{?t 500 ?limit 1000})))
    (t/is (true? (sut/eval-expr '(<= ?a 100) '{?a 100})))
    (t/is (true? (sut/eval-expr '(= ?x ?y) '{?x 5 ?y 5})))
    (t/is (true? (sut/eval-expr '(not= ?x ?y) '{?x 5 ?y 10})))))

(t/deftest eval-expr-arithmetic-test
  (t/testing "Arithmetic operators"
    (t/is (= 15 (sut/eval-expr '(+ ?a ?b) '{?a 10 ?b 5})))
    (t/is (= 50 (sut/eval-expr '(* ?q ?p) '{?q 5 ?p 10})))
    (t/is (= 1 (sut/eval-expr '(mod ?x 3) '{?x 7})))))

(t/deftest eval-expr-string-test
  (t/testing "String functions with str/ prefix"
    (t/is (true? (sut/eval-expr '(str/starts-with? ?r "/public/")
                                '{?r "/public/docs"})))
    (t/is (false? (sut/eval-expr '(str/starts-with? ?r "/public/")
                                 '{?r "/private/docs"})))
    (t/is (true? (sut/eval-expr '(str/includes? ?s "needle")
                                '{?s "haystackneedlehaystack"})))
    (t/is (= "HELLO" (sut/eval-expr '(str/upper-case ?s) '{?s "hello"})))))

(t/deftest eval-expr-nested-test
  (t/testing "Nested expressions evaluate inside-out"
    (t/is (true? (sut/eval-expr '(and (>= ?t 0) (< ?t ?limit))
                                '{?t 500 ?limit 1000})))
    (t/is (false? (sut/eval-expr '(and (>= ?t 0) (< ?t ?limit))
                                 '{?t -1 ?limit 1000})))
    (t/is (true? (sut/eval-expr '(<= (* ?q ?p) ?b)
                                '{?q 5 ?p 10 ?b 100})))))

(t/deftest eval-expr-unknown-fn-test
  (t/testing "Unknown function throws"
    (t/is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Unknown function"
                            (sut/eval-expr '(evil-fn 1 2) {})))))

(t/deftest eval-when-test
  (t/testing "All guards must pass"
    (t/is (true? (sut/eval-when '[(> ?t 0) (< ?t 1000)] '{?t 500})))
    (t/is (false? (sut/eval-when '[(> ?t 0) (< ?t 1000)] '{?t 1500}))))
  (t/testing "Nil/empty guards always pass"
    (t/is (true? (sut/eval-when nil {})))
    (t/is (true? (sut/eval-when [] {})))))

(t/deftest eval-let-test
  (t/testing "Let bindings extend the environment"
    (let [env (sut/eval-let '[[?total (* ?q ?p)]] '{?q 5 ?p 10})]
      (t/is (= 50 (get env '?total)))))
  (t/testing "Sequential bindings can reference earlier ones"
    (let [env (sut/eval-let '[[?a (+ ?x 1)] [?b (* ?a 2)]] '{?x 5})]
      (t/is (= 6 (get env '?a)))
      (t/is (= 12 (get env '?b)))))
  (t/testing "Nil let-bindings returns env unchanged"
    (t/is (= '{?x 5} (sut/eval-let nil '{?x 5})))))

;;; ---- Integration: rules/checks with :when/:let ----

(t/deftest fire-rule-with-when-test
  (t/testing "Rule fires only when guard passes"
    (let [facts [[:item "A" 50] [:item "B" 200]]
          rule  '{:id   :cheap-item
                  :head [:cheap ?name]
                  :body [[:item ?name ?price]]
                  :when [(< ?price 100)]}
          results (sut/fire-rule rule facts)]
      (t/is (= 1 (count results)))
      (t/is (= [:cheap "A"] (:fact (first results)))))))

(t/deftest fire-rule-with-let-and-when-test
  (t/testing "Rule with :let computes value and :when filters"
    (let [facts [[:line-item "X" 3 10] [:line-item "Y" 2 200]]
          rule  '{:id   :compute-total
                  :head [:invoice-total ?item ?total]
                  :body [[:line-item ?item ?qty ?price]]
                  :let  [[?total (* ?qty ?price)]]
                  :when [(< ?total 100)]}
          results (sut/fire-rule rule facts)]
      (t/is (= 1 (count results)))
      (t/is (= [:invoice-total "X" 30] (:fact (first results)))))))

(t/deftest eval-check-with-when-pass-test
  (t/testing "Check passes when guard passes"
    (let [store {[:time 500] #{:authorizer}}
          check '{:id :check-expiry :query [[:time ?t]] :when [(< ?t 1000)]}
          result (sut/eval-check check store)]
      (t/is (= :pass (:result result))))))

(t/deftest eval-check-with-when-fail-test
  (t/testing "Check fails when pattern matches but guard fails"
    (let [store {[:time 1500] #{:authorizer}}
          check '{:id :check-expiry :query [[:time ?t]] :when [(< ?t 1000)]}
          result (sut/eval-check check store)]
      (t/is (= :fail (:result result))))))

(t/deftest reject-if-with-when-test
  (t/testing "Reject-if with guard: match + guard pass = fail"
    (let [store {[:time 1500] #{0} [:expiry 1000] #{0}}
          check '{:id :reject-expired :kind :reject
                  :query [[:time ?t] [:expiry ?exp]]
                  :when [(>= ?t ?exp)]}
          result (sut/eval-check check store)]
      (t/is (= :fail (:result result)))))
  (t/testing "Reject-if with guard: match + guard fail = pass"
    (let [store {[:time 500] #{0} [:expiry 1000] #{0}}
          check '{:id :reject-expired :kind :reject
                  :query [[:time ?t] [:expiry ?exp]]
                  :when [(>= ?t ?exp)]}
          result (sut/eval-check check store)]
      (t/is (= :pass (:result result))))))

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

;;; ---- Third-party block scope tests ----

(t/deftest authorizer-sees-trusted-third-party-facts
  (t/testing "Authorizer can see third-party block facts when trusted"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:role "alice" :verified]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token
                                 :trusted-block-indices #{1}
                                 :authorizer
                                 {:checks [{:id    :c1
                                            :query [[:role "alice" :verified]]}]})]
      (t/is (true? (:valid? result))))))

(t/deftest authorizer-rules-derive-from-trusted-third-party-facts
  (t/testing "Authorizer rules can derive facts from trusted third-party data"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:email "alice" "alice@example.com"]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token
                                 :trusted-block-indices #{1}
                                 :authorizer
                                 {:rules   '[{:id   :has-email
                                              :head [:verified ?u]
                                              :body [[:user ?u] [:email ?u ?e]]}]
                                  :checks  [{:id    :c1
                                             :query [[:verified "alice"]]}]})]
      (t/is (true? (:valid? result))))))

(t/deftest policies-see-trusted-third-party-facts
  (t/testing "Authorizer policies can match against trusted third-party facts"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:idp-verified "alice"]]
                   :rules  []
                   :checks []}]}
          result (sut/eval-token token
                                 :trusted-block-indices #{1}
                                 :authorizer
                                 {:policies [{:kind  :allow
                                              :query [[:idp-verified "alice"]]}]})]
      (t/is (true? (:valid? result))))))

(t/deftest first-party-block-cannot-see-third-party-facts
  (t/testing "First-party block cannot see trusted third-party facts"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:idp-verified "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  []
                   :rules  []
                   :checks [{:id    :c1
                             :query [[:idp-verified "alice"]]}]}]}
          result (sut/eval-token token
                                 :trusted-block-indices #{1})]
      (t/is (false? (:valid? result))))))

(t/deftest third-party-block-own-checks-work
  (t/testing "Third-party block's own checks work normally"
    (let [token {:blocks
                 [{:facts  [[:user "alice"]]
                   :rules  []
                   :checks []}
                  {:facts  [[:tp-data "x"]]
                   :rules  []
                   :checks [{:id    :tp-check
                             :query [[:user "alice"]]}]}]}
          result (sut/eval-token token
                                 :trusted-block-indices #{1})]
      (t/is (true? (:valid? result))))))

(t/deftest nil-trusted-block-indices-backward-compat
  (t/testing "nil trusted-block-indices behaves like before (no third-party trust)"
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

;; --- Fixpoint safety: circular rules, explosion, termination ---

(t/deftest circular-rules-terminate
  (t/testing "Mutually recursive rules reach fixpoint without looping"
    (let [token {:blocks [{:facts [[:a 1]]
                           :rules [{:id :a-to-b :head [:b '?x] :body [[:a '?x]]}
                                   {:id :b-to-a :head [:a '?x] :body [[:b '?x]]}]
                           :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind :allow
                                              :query [[:b 1]]}]})]
      (t/is (:valid? result)))))

(t/deftest circular-rules-no-bootstrap
  (t/testing "Circular rules with no seed facts produce nothing"
    (let [token {:blocks [{:facts []
                           :rules [{:id :a-to-b :head [:b '?x] :body [[:a '?x]]}
                                   {:id :b-to-a :head [:a '?x] :body [[:b '?x]]}]
                           :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind :allow
                                              :query [[:b 1]]}]})]
      (t/is (not (:valid? result))))))

(t/deftest fact-explosion-capped
  (t/testing "Unbounded rule generation stops at max-facts limit"
    (let [token {:blocks [{:facts [[:n 1]]
                           :rules '[{:id   :grow
                                     :head [:n ?next]
                                     :body [[:n ?x]]
                                     :let  [[?next (+ ?x 1)]]
                                     :when [(< ?x 2000)]}]
                           :checks []}]}
          result-low (sut/eval-token token
                                     :authorizer
                                     {:policies [{:kind :allow
                                                  :query [[:n 100]]}]})
          result-high (sut/eval-token token
                                      :authorizer
                                      {:policies [{:kind :allow
                                                   :query [[:n 1500]]}]})]
      (t/is (:valid? result-low))
      (t/is (not (:valid? result-high))))))

(t/deftest self-referential-rule-terminates
  (t/testing "Rule that derives its own input terminates after one round"
    (let [token {:blocks [{:facts [[:x 1]]
                           :rules [{:id :self :head [:x '?v] :body [[:x '?v]]}]
                           :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind :allow
                                              :query [[:x 1]]}]})]
      (t/is (:valid? result)))))

(t/deftest transitive-chain-terminates
  (t/testing "Long transitive chain reaches fixpoint"
    (let [edges (mapv (fn [i] [:edge i (inc i)]) (range 1 10))
          token {:blocks [{:facts (into [[:reachable 1 1]] edges)
                           :rules [{:id   :trans
                                    :head [:reachable '?a '?c]
                                    :body [[:reachable '?a '?b]
                                           [:edge '?b '?c]]}]
                           :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind :allow
                                              :query [[:reachable 1 10]]}]})]
      (t/is (:valid? result)))))
