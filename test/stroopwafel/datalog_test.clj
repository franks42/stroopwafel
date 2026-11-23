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
        {[:can "alice" :read "file-1"] #{#{0}}}
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
    (t/is (= [:deny :check-failed] ((juxt :result :reason) (:explain result))))
    (t/is (= :fail (get-in result [:explain :checks 0 :result])))))

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
    (let [store {[:admin "mallory"] #{#{0}}}
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
    (let [store {[:time 500] #{#{:authorizer}}}
          check '{:id :check-expiry :query [[:time ?t]] :when [(< ?t 1000)]}
          result (sut/eval-check check store)]
      (t/is (= :pass (:result result))))))

(t/deftest eval-check-with-when-fail-test
  (t/testing "Check fails when pattern matches but guard fails"
    (let [store {[:time 1500] #{#{:authorizer}}}
          check '{:id :check-expiry :query [[:time ?t]] :when [(< ?t 1000)]}
          result (sut/eval-check check store)]
      (t/is (= :fail (:result result))))))

(t/deftest reject-if-with-when-test
  (t/testing "Reject-if with guard: match + guard pass = fail"
    (let [store {[:time 1500] #{#{0}} [:expiry 1000] #{#{0}}}
          check '{:id :reject-expired :kind :reject
                  :query [[:time ?t] [:expiry ?exp]]
                  :when [(>= ?t ?exp)]}
          result (sut/eval-check check store)]
      (t/is (= :fail (:result result)))))
  (t/testing "Reject-if with guard: match + guard fail = pass"
    (let [store {[:time 500] #{#{0}} [:expiry 1000] #{#{0}}}
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

(t/deftest fact-explosion-fails-closed
  (t/testing "Unbounded rule generation stops at a limit and denies, even
              for a query that matched before the limit"
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
      (t/is (false? (:valid? result-low)))
      (t/is (= :limit-exceeded (-> result-low :error :type)))
      (t/is (false? (:valid? result-high))))))

;; --- Fixpoint limits fail closed ---
;; A fixpoint cut short leaves derived facts missing. A :reject check or a
;; :deny policy over a missing fact would then pass, so reaching a limit
;; must deny, never evaluate the partial store.

(defn- chain-token
  "Edges 0→1→…→n and a transitive :reach rule: n(n+1)/2 derived facts,
   n iterations."
  [n checks]
  {:blocks [{:facts  (mapv (fn [i] [:edge i (inc i)]) (range n))
             :rules  '[{:id :reach-1 :head [:reach ?a ?b] :body [[:edge ?a ?b]]}
                       {:id   :reach-n
                        :head [:reach ?a ?c]
                        :body [[:reach ?a ?b] [:edge ?b ?c]]}]
             :checks checks}]})

(defn- deny-reach [n]
  {:policies [{:kind :deny :query [[:reach 0 n]]}
              {:kind :allow :query [[:edge 0 1]]}]})

(t/deftest deny-policy-fails-closed-at-fact-limit
  (t/testing "under the fact limit, the deny policy matches"
    (t/is (false? (:valid? (sut/eval-token (chain-token 40 [])
                                           :authorizer (deny-reach 40))))))
  (t/testing "over the fact limit, the deny fact is never derived; deny anyway"
    (let [result (sut/eval-token (chain-token 50 [])
                                 :authorizer (deny-reach 50))]
      (t/is (false? (:valid? result)))
      (t/is (= {:type :limit-exceeded :limit :max-facts :max 1000}
               (select-keys (:error result) [:type :limit :max]))))))

(t/deftest reject-check-fails-closed-at-fact-limit
  (let [result (sut/eval-token
                (chain-token 50 [{:id :no-far :kind :reject :query [[:reach 0 50]]}]))]
    (t/is (false? (:valid? result)))
    (t/is (= :max-facts (-> result :error :limit)))))

(t/deftest fails-closed-at-iteration-limit
  (t/testing "a long chain from one start: few facts, more than 100 iterations"
    (let [token  {:blocks [{:facts (into [[:reachable 0 0]]
                                         (map (fn [i] [:edge i (inc i)]))
                                         (range 150))
                            :rules '[{:id   :trans
                                      :head [:reachable ?a ?c]
                                      :body [[:reachable ?a ?b] [:edge ?b ?c]]}]}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind :deny :query [[:reachable 0 150]]}
                                             {:kind :allow :query [[:reachable 0 1]]}]})]
      (t/is (false? (:valid? result)))
      (t/is (= {:type :limit-exceeded :limit :max-iterations :max 100}
               (select-keys (:error result) [:type :limit :max]))))))

(t/deftest limits-are-configurable
  (t/testing "raised limits let the 50-chain reach its fixpoint"
    (let [limits {:max-facts 5000}]
      (t/is (= {:valid? false}
               (sut/eval-token (chain-token 50 []) :authorizer (deny-reach 50)
                               :limits limits))
            "the deny policy matches; no limit error")
      (t/is (= {:valid? true}
               (sut/eval-token (chain-token 50 [])
                               :authorizer {:policies [{:kind :allow :query [[:reach 0 50]]}]}
                               :limits limits)))))
  (t/testing "lowered limits deny a small evaluation"
    (t/is (= :max-iterations
             (-> (sut/eval-token (chain-token 5 [])
                                 :authorizer {:policies [{:kind :allow :query [[:edge 0 1]]}]}
                                 :limits {:max-iterations 2})
                 :error :limit))))
  (t/testing "a fixpoint reached exactly at the limits is not an error"
    ;; chain of 5: 5 edges + 15 reach facts = 20; 5 rounds that add facts
    ;; plus one that adds none
    (t/is (= {:valid? true}
             (sut/eval-token (chain-token 5 [])
                             :authorizer {:policies [{:kind :allow :query [[:reach 0 5]]}]}
                             :limits {:max-facts 20 :max-iterations 6}))))
  (t/testing "limits must be positive integers"
    (t/is (thrown-with-msg? clojure.lang.ExceptionInfo #"limits"
                            (sut/eval-token (chain-token 5 []) :limits {:max-facts 0})))
    (t/is (thrown-with-msg? clojure.lang.ExceptionInfo #"limits"
                            (sut/eval-token (chain-token 5 []) :limits {:max-fact 10})))))

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

;; ---------------------------------------------------------------------------
;; Arity: a pattern matches a fact only when both have the same length.
;; Before 0.13.0, unify* zipped pattern and fact with (map vector …), which
;; truncates to the shorter one, so mismatched arities matched and failed open.
;; ---------------------------------------------------------------------------

(t/deftest unify-requires-equal-arity
  (t/testing "pattern longer than fact does not unify"
    (t/is (nil? (sut/unify '[:user ?u ?role] [:user "alice"]))))
  (t/testing "pattern shorter than fact does not unify"
    (t/is (nil? (sut/unify '[:right ?u] [:right "alice" :read]))))
  (t/testing "equal arity still unifies"
    (t/is (= '{?u "alice"} (:env (sut/unify '[:user ?u] [:user "alice"]))))))

(t/deftest check-arity-mismatch-fails
  (let [store {[:user "alice"] #{#{0}}}]
    (t/testing "check pattern longer than the fact does not pass"
      (t/is (= :fail (:result (sut/eval-check {:id :c :query '[[:user ?u ?role]]}
                                              store)))))
    (t/testing "check pattern shorter than the fact does not pass"
      (t/is (= :fail (:result (sut/eval-check {:id :c :query '[[:user]]}
                                              store)))))))

(t/deftest reject-check-arity-mismatch-does-not-match
  (t/testing "a reject pattern of another arity does not match the fact"
    (let [store {[:admin "mallory"] #{#{0}}}]
      (t/is (= :pass (:result (sut/eval-check {:id :r :kind :reject
                                               :query '[[:admin ?u ?x]]}
                                              store)))))))

(t/deftest allow-policy-arity-mismatch-denies
  (t/testing "a shorter allow-policy pattern does not match a longer fact"
    (let [token  {:blocks [{:facts [[:right "alice" :read]] :rules [] :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind  :allow
                                              :query '[[:right ?u]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest rule-body-arity-mismatch-derives-nothing
  (t/testing "a longer rule-body pattern does not derive from a shorter fact"
    (let [token  {:blocks [{:facts  [[:user "alice"]]
                            :rules  [{:id   :r
                                      :head '[:admin ?u]
                                      :body '[[:user ?u ?x]]}]
                            :checks []}]}
          result (sut/eval-token token
                                 :authorizer
                                 {:policies [{:kind  :allow
                                              :query '[[:admin ?u]]}]})]
      (t/is (false? (:valid? result))))))

(t/deftest eval-expr-error-does-not-leak-env
  (t/testing "ex-data names the unbound variable but carries no bound values"
    (let [data (try (sut/eval-expr '?x '{?t "secret-token-id"})
                    (catch clojure.lang.ExceptionInfo e (ex-data e)))]
      (t/is (= '{:variable ?x} data))))
  (t/testing "a guard error raised through eval-check carries no bound values"
    (let [data (try (sut/eval-check {:id :c :query '[[:user ?u]] :when '[(= ?x ?u)]}
                                    {[:user "alice"] #{#{0}}})
                    (catch clojure.lang.ExceptionInfo e (ex-data e)))]
      (t/is (= '{:variable ?x} data)))))

(t/deftest fixpoint-records-derivations-only-on-request
  (let [rules [[0 [{:id :r :head '[:can ?u] :body '[[:right ?u]]}]]]
        store (sut/insert-facts (sut/make-fact-store) [[:right "alice"]] #{0})]
    (t/testing "explain? records rule, block, bindings and proof per derived fact"
      (t/is (= {[:can "alice"] [{:rule   :r
                                 :block  0
                                 :origin #{0}
                                 :env    '{?u "alice"}
                                 :proof  [[:right "alice"]]}]}
               (:derivations (sut/fixpoint rules store :explain? true)))))
    (t/testing "without explain? nothing is recorded"
      (t/is (nil? (:derivations (sut/fixpoint rules store)))))
    (t/testing "apply-rules-scoped still returns the bare store"
      (t/is (= {[:right "alice"] #{#{0}} [:can "alice"] #{#{0}}}
               (sut/apply-rules-scoped rules store))))))

(t/deftest store-keeps-minimal-origin-sets
  (let [s0 (sut/insert-fact (sut/make-fact-store) [:f] #{0 1})]
    (t/is (= {[:f] #{#{0 1}}} s0))
    (t/testing "an incomparable origin set is kept alongside"
      (t/is (= {[:f] #{#{0 1} #{:authorizer}}} (sut/insert-fact s0 [:f] #{:authorizer}))))
    (t/testing "a subset replaces the supersets it subsumes"
      (t/is (= {[:f] #{#{0}}} (sut/insert-fact s0 [:f] #{0}))))
    (t/testing "a superset of a kept set adds nothing"
      (t/is (identical? s0 (sut/insert-fact s0 [:f] #{0 1 2}))))
    (t/testing "the same fact stated by two blocks keeps both origins (no union)"
      (t/is (= {[:f] #{#{0} #{1}}}
               (-> (sut/make-fact-store)
                   (sut/insert-facts [[:f]] #{0})
                   (sut/insert-facts [[:f]] #{1})))))))

(t/deftest scope-sees-a-fact-through-any-visible-origin
  (let [store (-> (sut/make-fact-store)
                  (sut/insert-fact [:f] #{0 1})
                  (sut/insert-fact [:f] #{:authorizer}))]
    (t/is (= [[#{:authorizer} [:f]]] (sut/facts-for-scope store #{0 :authorizer})))
    (t/is (= #{[#{0 1} [:f]] [#{:authorizer} [:f]]}
             (set (sut/facts-for-scope store #{0 1 :authorizer}))))))

(t/deftest max-facts-counts-origin-sets
  (t/testing "appended blocks re-deriving the same facts cannot grow the store unbounded"
    (let [base   {:facts [[:a 1] [:a 2] [:a 3]]}
          copier (fn [_] {:rules '[{:id :copy :head [:b ?x] :body [[:a ?x]]}]})
          token  {:blocks (into [base] (map copier) (range 6))}
          result (sut/eval-token token :limits {:max-facts 15})]
      (t/testing "6 blocks x 3 facts = 18 [:b] entries with distinct origins, plus 3 [:a]"
        (t/is (false? (:valid? result)))
        (t/is (= :max-facts (get-in result [:error :limit])))))))
