(ns stroopwafel.graph-test
  (:require [stroopwafel.graph :as sut]
            [clojure.test :as t]))

;; Hand-built explain maps in the flat shape evaluate produces.
;; End-to-end evaluate -> graph tests live in core_test.

(t/deftest explain->graph-pass-with-derivation
  (let [explain {:type     :check
                 :check-id :c1
                 :result   :pass
                 :because  [[:can "alice" :read "file-1"]]
                 :facts    {[:can "alice" :read "file-1"]
                            {:origin      #{0}
                             :derivations [{:rule  :can-from-right
                                            :block 0
                                            :env   '{?u "alice"}
                                            :proof [[:right "alice" :read "file-1"]
                                                    [:resource "file-1"]]}]}
                            [:right "alice" :read "file-1"] {:origin #{0} :stated? true}
                            [:resource "file-1"]            {:origin #{0} :stated? true}}}
        graph   (sut/explain->graph explain)]
    (t/is (= :n1 (:root graph)))
    (t/is (= [:check :fact :derivation :fact :fact]
             (mapv #(get-in graph [:nodes % :kind]) [:n1 :n2 :n3 :n4 :n5])))
    (t/is (= [{:from :n1 :to :n2 :label :because}
              {:from :n2 :to :n3 :label :derived-by}
              {:from :n3 :to :n4 :label :uses}
              {:from :n3 :to :n5 :label :uses}]
             (:edges graph)))))

(t/deftest explain->graph-fail-missing
  (let [graph (sut/explain->graph {:type     :check
                                   :check-id :c2
                                   :result   :fail
                                   :missing  [[:can "alice" :write "file-1"]]})]
    (t/is (= {:id :n2 :kind :missing-fact :fact [[:can "alice" :write "file-1"]]}
             (get-in graph [:nodes :n2])))
    (t/is (= [{:from :n1 :to :n2 :label :missing}] (:edges graph)))))

(t/deftest explain->graph-fact-without-table-entry
  (t/testing "a :because fact missing from :facts (e.g. truncated) is still a node"
    (let [graph (sut/explain->graph {:type :check :check-id :c :result :pass
                                     :because [[:user "alice"]]})]
      (t/is (= {:id :n2 :kind :fact :fact [:user "alice"] :origin nil :stated? false}
               (get-in graph [:nodes :n2]))))))

(t/deftest explain->graph-deterministic-ids
  (let [explain {:type :check :check-id :c1 :result :pass
                 :because [[:user "alice"]]
                 :facts {[:user "alice"] {:origin #{0} :stated? true}}}]
    (t/is (= (sut/explain->graph explain) (sut/explain->graph explain)))))

(t/deftest unknown-explain-error-does-not-leak-facts
  (t/testing "ex-data describes the explain's shape, not its facts or bindings"
    (let [explain {:fact    [:user "alice"]
                   :matches [{:env '{?u "alice"}}]}
          data    (try (sut/explain->graph explain)
                       (catch clojure.lang.ExceptionInfo e (ex-data e)))]
      (t/is (= {:node-keys  #{:fact :matches}
                :node-class "clojure.lang.PersistentArrayMap"}
               data))
      (t/is (not (re-find #"alice" (pr-str data)))))))
