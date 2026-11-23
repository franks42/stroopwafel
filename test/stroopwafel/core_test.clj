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

(t/deftest evaluate-fails-closed-at-a-limit
  (t/testing "evaluate passes :limits through and reports a limit as a deny"
    (let [token  {:blocks [{:facts (mapv (fn [i] [:edge i (inc i)]) (range 10))
                            :rules '[{:id :r1 :head [:reach ?a ?b] :body [[:edge ?a ?b]]}
                                     {:id   :rn
                                      :head [:reach ?a ?c]
                                      :body [[:reach ?a ?b] [:edge ?b ?c]]}]}]}
          policy {:policies [{:kind :allow :query [[:edge 0 1]]}]}]
      (t/is (= {:valid? true} (sut/evaluate token :authorizer policy)))
      (let [result (sut/evaluate token :authorizer policy :limits {:max-facts 30})]
        (t/is (false? (:valid? result)))
        (t/is (= :max-facts (-> result :error :limit)))))))

;; ---------------------------------------------------------------------------
;; Explain: one flat shape for :explain? true and :all — evaluate -> graph.
;; ---------------------------------------------------------------------------

(def ^:private delegation-token
  {:blocks [{:facts  [[:right "alice" :read "file-1"]]
             :rules  []
             :checks []}
            {:facts  []
             :rules  [{:id   :can-from-right
                       :head '[:can ?u ?a ?r]
                       :body '[[:right ?u ?a ?r]]}]
             :checks [{:id    :alice-can-read
                       :query '[[:can "alice" :read "file-1"]]}]}]})

(defn- nodes-of-kind [graph kind]
  (filter #(= kind (:kind %)) (vals (:nodes graph))))

(t/deftest explain-decision-shape
  (t/is (= {:valid?  true
            :explain {:type     :decision
                      :result   :allow
                      :reason   :no-policies
                      :checks   [{:type     :check
                                  :check-id :alice-can-read
                                  :block    1
                                  :result   :pass
                                  :because  [[:can "alice" :read "file-1"]]
                                  :matches  [{:env    {}
                                              :origin #{0 1}
                                              :facts  [[:can "alice" :read "file-1"]]}]}]
                      :policies []
                      :facts    {[:can "alice" :read "file-1"]
                                 {:origin      #{0 1}
                                  :derivations [{:rule  :can-from-right
                                                 :block 1
                                                 :env   '{?u "alice" ?a :read ?r "file-1"}
                                                 :proof [[:right "alice" :read "file-1"]]}]}
                                 [:right "alice" :read "file-1"]
                                 {:origin #{0} :stated? true}}}}
           (sut/evaluate delegation-token :explain? true))))

(t/deftest graph-renders-evaluate-output
  (let [graph (sut/graph (:explain (sut/evaluate delegation-token :explain? true)))]
    (t/is (= {:n1 {:id :n1 :kind :decision :result :allow :reason :no-policies}
              :n2 {:id :n2 :kind :check :check-id :alice-can-read :block 1 :result :pass}
              :n3 {:id :n3 :kind :fact :fact [:can "alice" :read "file-1"]
                   :origin #{0 1} :stated? false}
              :n4 {:id :n4 :kind :derivation :rule :can-from-right :block 1
                   :env '{?u "alice" ?a :read ?r "file-1"}}
              :n5 {:id :n5 :kind :fact :fact [:right "alice" :read "file-1"]
                   :origin #{0} :stated? true}}
             (:nodes graph)))
    (t/is (= [{:from :n1 :to :n2 :label :check}
              {:from :n2 :to :n3 :label :because}
              {:from :n3 :to :n4 :label :derived-by}
              {:from :n4 :to :n5 :label :uses}]
             (:edges graph)))
    (t/is (= :n1 (:root graph)))))

(t/deftest explain-covers-every-pattern-of-a-join-check
  (let [token  {:blocks [{:facts  [[:user "alice"] [:right "alice" :read]]
                          :rules  []
                          :checks [{:id    :join
                                    :query '[[:user ?u] [:right ?u :read]]}]}]}]
    (t/is (= [[:user "alice"] [:right "alice" :read]]
             (get-in (sut/evaluate token :explain? true) [:explain :checks 0 :because])))))

(t/deftest graph-shares-repeated-facts
  (t/testing "a fact reached along two proof paths is one node"
    (let [token {:blocks [{:facts  [[:edge 1 2] [:edge 2 3] [:edge 1 3]]
                           :rules  [{:id   :step
                                     :head '[:path ?a ?b]
                                     :body '[[:edge ?a ?b]]}
                                    {:id   :pair
                                     :head '[:two ?a ?c]
                                     :body '[[:path ?a ?b] [:path ?b ?c] [:path ?a ?c]]}]
                           :checks [{:id :c :query '[[:two 1 3] [:edge 1 3]]}]}]}
          graph (sut/graph (:explain (sut/evaluate token :explain? true)))
          facts (map :fact (nodes-of-kind graph :fact))]
      (t/is (= (count facts) (count (set facts))))
      (t/is (= 1 (count (filter #{[:edge 1 3]} facts)))))))

(t/deftest reject-failure-shows-the-matching-facts
  (let [token  {:blocks [{:facts  [[:admin "mallory"]]
                          :rules  []
                          :checks [{:id :no-admin :kind :reject
                                    :query '[[:admin ?u]]}]}]}
        result (sut/evaluate token :explain? true)
        graph  (sut/graph (:explain result))]
    (t/is (false? (:valid? result)))
    (t/is (= [[:admin "mallory"]] (get-in result [:explain :checks 0 :because])))
    (t/is (= {[:admin "mallory"] {:origin #{0} :stated? true}}
             (get-in result [:explain :facts])))
    (t/is (= [{:from :n1 :to :n2 :label :check}
              {:from :n2 :to :n3 :label :rejected-by}]
             (:edges graph)))))

(t/deftest reject-pass-graph-has-only-the-check
  (let [token {:blocks [{:facts  [[:user "alice"]]
                         :rules  []
                         :checks [{:id :no-admin :kind :reject
                                   :query '[[:admin ?u]]}]}]}
        graph (sut/graph (:explain (sut/evaluate token :explain? true)))]
    (t/is (= #{:decision :check} (set (map :kind (vals (:nodes graph))))))
    (t/is (= [{:from :n1 :to :n2 :label :check}] (:edges graph)))))

;; --- :explain? :all — every reason -----------------------------------------

(def ^:private two-route-token
  {:blocks [{:facts  [[:right "alice" :read]
                      [:member "alice" :readers]
                      [:group-right :readers :read]]
             :rules  [{:id   :direct
                       :head '[:can ?u ?a]
                       :body '[[:right ?u ?a]]}
                      {:id   :via-group
                       :head '[:can ?u ?a]
                       :body '[[:member ?u ?g] [:group-right ?g ?a]]}]
             :checks [{:id :c :query '[[:can "alice" :read]]}]}]})

(t/deftest explain-all-shows-every-derivation
  (let [rules-of (fn [mode]
                   (->> (sut/evaluate two-route-token :explain? mode)
                        :explain :facts
                        (#(get % [:can "alice" :read]))
                        :derivations
                        (mapv :rule)))]
    (t/is (= [:direct] (rules-of true)))
    (t/is (= [:direct :via-group] (rules-of :all)))))

(t/deftest graph-keeps-each-derivation-separate
  (let [graph   (sut/graph (:explain (sut/evaluate two-route-token :explain? :all)))
        derivs  (nodes-of-kind graph :derivation)
        uses-of (fn [d] (->> (:edges graph)
                             (filter #(and (= (:id d) (:from %)) (= :uses (:label %))))
                             (map #(get-in graph [:nodes (:to %) :fact]))
                             set))]
    (t/is (= {:direct    #{[:right "alice" :read]}
              :via-group #{[:member "alice" :readers] [:group-right :readers :read]}}
             (into {} (map (juxt :rule uses-of)) derivs)))))

(def ^:private cyclic-token
  {:blocks [{:facts  [[:edge 1 2] [:edge 2 1]]
             :rules  [{:id   :base
                       :head '[:path ?a ?b]
                       :body '[[:edge ?a ?b]]}
                      {:id   :trans
                       :head '[:path ?a ?c]
                       :body '[[:path ?a ?b] [:edge ?b ?c]]}]
             :checks [{:id :c :query '[[:path 1 2]]}]}]})

(t/deftest explain-all-includes-circular-reasons
  (let [facts (get-in (sut/evaluate cyclic-token :explain? :all) [:explain :facts])]
    (t/testing "[:path 1 2] is derived directly and via [:path 1 1]"
      (t/is (= #{[[:edge 1 2]] [[:path 1 1] [:edge 1 2]]}
               (set (map :proof (get-in facts [[:path 1 2] :derivations]))))))
    (t/testing "[:path 1 1] is derived via [:path 1 2] — the loop"
      (t/is (some #{[[:path 1 2] [:edge 2 1]]}
                  (map :proof (get-in facts [[:path 1 1] :derivations])))))))

(t/deftest graph-draws-cycles-as-edges-back
  (let [graph    (sut/graph (:explain (sut/evaluate cyclic-token :explain? :all)))
        id-of    (into {} (map (juxt :fact :id)) (nodes-of-kind graph :fact))
        path-1-2 (id-of [:path 1 2])]
    (t/is (= (count (nodes-of-kind graph :fact))
             (count (set (map :fact (nodes-of-kind graph :fact))))))
    (t/testing "some derivation :uses the node it ultimately explains"
      (t/is (some #(and (= :uses (:label %)) (= path-1-2 (:to %)))
                  (:edges graph))))
    (t/is (= graph (sut/graph (:explain (sut/evaluate cyclic-token :explain? :all))))
          "node ids are deterministic")))

(t/deftest explain-all-because-covers-every-match
  (let [token {:blocks [{:facts  [[:right "alice" :read] [:right "bob" :read]]
                         :rules  []
                         :checks [{:id :c :query '[[:right ?u :read]]}]}]}
        because (fn [mode] (set (get-in (sut/evaluate token :explain? mode)
                                        [:explain :checks 0 :because])))]
    (t/is (= 1 (count (because true))))
    (t/is (= #{[:right "alice" :read] [:right "bob" :read]} (because :all)))))

(t/deftest explain-all-truncates-instead-of-denying
  (let [n      6
        edges  (for [a (range n) b (range n) :when (not= a b)] [:edge a b])
        token  {:blocks [{:facts  (vec edges)
                          :rules  (:rules (first (:blocks cyclic-token)))
                          :checks [{:id :c :query '[[:path 0 1]]}]}]}
        capped (sut/evaluate token :explain? :all :limits {:max-derivations 20})
        full   (sut/evaluate token :explain? :all)]
    (t/is (true? (:valid? capped)) "the cap never changes the decision")
    (t/is (true? (get-in capped [:explain :truncated?])))
    (t/is (nil? (get-in full [:explain :truncated?])))))

;; --- Finding 5: explain shows the whole decision ---------------------------

(def ^:private policy-token
  {:blocks [{:facts  [[:right "alice" :read "file-1"]]
             :rules  []
             :checks [{:id :has-right :query '[[:right ?u :read ?r]]}]}]})

(t/deftest explain-names-the-deciding-allow-policy
  (let [explain (:explain (sut/evaluate policy-token :explain? true
                                        :authorizer
                                        {:facts    [[:user "alice"]]
                                         :checks   [{:id :is-user :query '[[:user ?u]]}]
                                         :policies [{:id    :no-banned
                                                     :kind  :deny
                                                     :query '[[:banned ?u]]}
                                                    {:kind  :allow
                                                     :query '[[:right ?u :read "file-1"]]}]}))]
    (t/is (= [:allow :policy] ((juxt :result :reason) explain)))
    (t/testing "every check, with its block"
      (t/is (= [[:has-right 0 :pass] [:is-user :authorizer :pass]]
               (mapv (juxt :check-id :block :result) (:checks explain)))))
    (t/testing "every evaluated policy, in order; the decider carries its evidence"
      (t/is (= [{:index 0 :id :no-banned :kind :deny :query '[[:banned ?u]]
                 :result :no-match}
                {:index   1 :kind :allow :query '[[:right ?u :read "file-1"]]
                 :result  :matched
                 :because [[:right "alice" :read "file-1"]]
                 :matches [{:env '{?u "alice"} :origin #{0}
                            :facts [[:right "alice" :read "file-1"]]}]}]
               (:policies explain))))
    (t/testing "one fact table for checks and policy"
      (t/is (= #{[:right "alice" :read "file-1"] [:user "alice"]}
               (set (keys (:facts explain))))))))

(t/deftest explain-names-the-deciding-deny-policy
  (let [explain (:explain (sut/evaluate policy-token :explain? true
                                        :authorizer
                                        {:policies [{:id :deny-reads :kind :deny
                                                     :query '[[:right ?u :read ?r]]}
                                                    {:id :allow-all :kind :allow
                                                     :query '[[:right ?u ?a ?r]]}]}))]
    (t/is (= [:deny :policy] ((juxt :result :reason) explain)))
    (t/is (= [[:deny-reads :matched]] (mapv (juxt :id :result) (:policies explain)))
          "policies after the decider are not evaluated, so not listed")))

(t/deftest explain-no-matching-policy
  (let [explain (:explain (sut/evaluate policy-token :explain? true
                                        :authorizer
                                        {:policies [{:id :p :kind :allow
                                                     :query '[[:admin ?u]]}]}))]
    (t/is (= [:deny :no-matching-policy] ((juxt :result :reason) explain)))
    (t/is (= [[:p :no-match]] (mapv (juxt :id :result) (:policies explain))))))

(t/deftest explain-lists-every-check-when-one-fails
  (let [token   {:blocks [{:facts  [[:user "alice"]]
                           :rules  []
                           :checks [{:id :a :query '[[:admin ?u]]}
                                    {:id :b :query '[[:user ?u]]}
                                    {:id :c :query '[[:owner ?u]]}]}]}
        explain (:explain (sut/evaluate token :explain? true
                                        :authorizer {:policies [{:kind :allow
                                                                 :query '[[:user ?u]]}]}))]
    (t/is (= [:deny :check-failed] ((juxt :result :reason) explain)))
    (t/is (= [[:a :fail] [:b :pass] [:c :fail]]
             (mapv (juxt :check-id :result) (:checks explain))))
    (t/is (= [] (:policies explain)) "policies are not evaluated after a failed check")))

(t/deftest explain-without-checks-is-not-nil
  (let [explain (:explain (sut/evaluate {:blocks [{:facts [[:user "alice"]]}]}
                                        :explain? true
                                        :authorizer {:policies [{:kind :allow
                                                                 :query '[[:user ?u]]}]}))]
    (t/is (= [:allow :policy []] ((juxt :result :reason :checks) explain)))))

(t/deftest explain-and-graph-at-a-limit
  (let [token  {:blocks [{:facts [[:edge 0 1] [:edge 1 2] [:edge 2 3]]
                          :rules '[{:id :r :head [:reach ?a ?b] :body [[:edge ?a ?b]]}
                                   {:id :t :head [:reach ?a ?c]
                                    :body [[:reach ?a ?b] [:edge ?b ?c]]}]}]}
        result (sut/evaluate token :explain? true :limits {:max-facts 5})
        graph  (sut/graph (:explain result))]
    (t/is (= {:type   :decision
              :result :deny
              :reason :limit-exceeded
              :error  (:error result)}
             (:explain result)))
    (t/is (= {:n1 {:id :n1 :kind :decision :result :deny :reason :limit-exceeded}}
             (:nodes graph)))))

(t/deftest graph-shows-checks-and-policies
  (let [graph (sut/graph (:explain (sut/evaluate policy-token :explain? true
                                                 :authorizer
                                                 {:policies [{:id :nope :kind :deny
                                                              :query '[[:banned ?u]]}
                                                             {:id :ok :kind :allow
                                                              :query '[[:right ?u :read ?r]]}]})))
        node  (fn [id] (get-in graph [:nodes id]))]
    (t/is (= [{:from :n1 :to :n2 :label :check}
              {:from :n2 :to :n3 :label :because}
              {:from :n1 :to :n4 :label :policy}
              {:from :n1 :to :n5 :label :policy}
              {:from :n5 :to :n3 :label :because}]
             (:edges graph)))
    (t/is (= {:id :n4 :kind :policy :index 0 :policy-id :nope :effect :deny :result :no-match}
             (node :n4)))
    (t/is (= {:id :n5 :kind :policy :index 1 :policy-id :ok :effect :allow :result :matched}
             (node :n5)))))

(t/deftest readme-example-explains-and-graphs
  (let [token  {:blocks [{:facts [[:right "alice" :read "/api/data"]
                                  [:right "alice" :write "/api/data"]]
                          :rules '[{:id   :can
                                    :head [:can ?u ?a ?r]
                                    :body [[:right ?u ?a ?r]]}]}
                         {:checks '[{:id :read-only :query [[:can ?u :read ?r]]}]}]}
        result (sut/evaluate token :explain? true
                             :authorizer {:facts    [[:time 1000]
                                                     [:request "alice" :read "/api/data"]]
                                          :checks   '[{:id    :not-expired
                                                       :query [[:time ?t]]
                                                       :when  [(< ?t 2000)]}]
                                          :policies '[{:kind  :allow
                                                       :query [[:request ?u ?a ?r]
                                                               [:can ?u ?a ?r]]}]})
        graph  (sut/graph (:explain result))]
    (t/is (true? (:valid? result)))
    (t/is (= [:allow :policy] ((juxt :result :reason) (:explain result))))
    (t/is (= {:decision 1 :check 2 :policy 1 :fact 4 :derivation 1}
             (frequencies (map :kind (vals (:nodes graph))))))))

(t/deftest signer-facts-without-authorizer-facts
  (t/testing "a trusted block's signer fact is added when the authorizer has no :facts"
    (let [idp-key (byte-array [1 2 3 4 5])
          token   {:blocks [{:facts [[:user "alice"]]}
                            {:facts [[:email "alice" "alice@idp.com"]]
                             :external-key idp-key}]}
          result  (sut/evaluate token :explain? true
                                :authorizer
                                {:trusted-external-keys [idp-key]
                                 :policies [{:kind  :allow
                                             :query '[[:block-signed-by 1 ?k]]}]})
          signer  (first (get-in result [:explain :policies 0 :because]))]
      (t/is (true? (:valid? result)))
      (t/is (= :block-signed-by (first signer)))
      (t/is (= 1 (second signer)))
      (t/is (= {:origin #{:authorizer} :stated? true}
               (get-in result [:explain :facts signer])))))
  (t/testing "with authorizer :facts, both they and the signer fact are present"
    (let [idp-key (byte-array [1 2 3 4 5])
          token   {:blocks [{:facts [[:user "alice"]]}
                            {:facts [] :external-key idp-key}]}
          result  (sut/evaluate token
                                :authorizer
                                {:trusted-external-keys [idp-key]
                                 :facts    [[:time 1000]]
                                 :policies [{:kind  :allow
                                             :query '[[:time ?t] [:block-signed-by 1 ?k]]}]})]
      (t/is (true? (:valid? result))))))

;; --- Pattern-length (arity) validation --------------------------------------

(def ^:private typo-token
  {:blocks [{:facts  [[:right "alice" :read]]
             :rules  [{:id :can :head '[:can ?u] :body '[[:right ?u :read]]}]
             :checks [{:id :no-writes :kind :reject :query '[[:right ?u]]}]}]})

(def ^:private typo-mismatch
  {:predicate :right
   :arities   {2 [{:block 0 :in :check :id :no-writes}]
               3 [{:block 0 :in :facts}
                  {:block 0 :in :rule-body :id :can}]}})

(t/deftest check-arity-finds-mismatches
  (t/is (= [typo-mismatch] (sut/check-arity typo-token)))
  (t/is (= [] (sut/check-arity delegation-token)) "consistent token"))

(t/deftest check-arity-on-a-policy-set-alone
  (t/testing "what a PDP runs before storing policies"
    (t/is (= [{:predicate :role
               :arities   {3 [{:block :authorizer :in :policy :id :admins}]
                           4 [{:block :authorizer :in :policy :index 1}]}}]
             (sut/check-arity {:blocks []}
                              :authorizer
                              {:policies [{:id :admins :kind :allow
                                           :query '[[:role ?u :admin]]}
                                          {:kind :deny
                                           :query '[[:role ?u :guest :x]]}]})))))

(t/deftest check-arity-ignores-variable-predicates
  (t/is (= [] (sut/check-arity {:blocks [{:facts  [[:a 1] [:b 1 2]]
                                          :checks [{:id :any :query '[[?p 1]]}]}]}))))

(t/deftest evaluate-warns-on-arity-mismatch-by-default
  (let [result (sut/evaluate typo-token)]
    (t/is (true? (:valid? result)) "the decision is unchanged")
    (t/is (= [(assoc typo-mismatch :type :arity-mismatch)] (:warnings result))))
  (t/is (= {:valid? true} (sut/evaluate delegation-token)) "no :warnings key when clean"))

(t/deftest evaluate-can-deny-on-arity-mismatch
  (let [result (sut/evaluate typo-token :arity-check :error :explain? true)]
    (t/is (= {:valid? false
              :error  {:type :arity-mismatch :mismatches [typo-mismatch]}
              :explain {:type   :decision
                        :result :deny
                        :reason :arity-mismatch
                        :error  {:type :arity-mismatch :mismatches [typo-mismatch]}}}
             result)))
  (t/is (= {:valid? true} (sut/evaluate delegation-token :arity-check :error))))

(t/deftest evaluate-arity-check-off
  (t/is (= {:valid? true} (sut/evaluate typo-token :arity-check :off))))

(t/deftest evaluate-rejects-unknown-arity-check-mode
  (t/is (thrown-with-msg? clojure.lang.ExceptionInfo #"arity-check"
                          (sut/evaluate typo-token :arity-check :loud))))
