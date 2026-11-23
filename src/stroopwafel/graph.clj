(ns stroopwafel.graph
  "Turns an explain map — the decision from `evaluate`, or a single check's
   from `stroopwafel.datalog/eval-check` — into nodes and edges. Pure data
   transformation — no authorization logic.

   Nodes:
     - `:decision`     — the result and its reason (the root of a decision)
     - `:check`        — a check, with its block and result
     - `:policy`       — an evaluated policy: index, id, effect, result
     - `:fact`         — a fact, with its origin and whether a block stated it
     - `:derivation`   — one rule application: rule, block and bindings
     - `:missing-fact` — the query of a check that found no match

   Edges:
     - decision `:check` → check, decision `:policy` → policy
     - check `:because` / `:rejected-by` / `:missing` → fact
     - matched policy `:because` → fact
     - fact `:derived-by` → derivation
     - derivation `:uses` → fact (the facts the rule body matched)

   Each fact is one node however many paths reach it, so circular
   derivations (`:explain? :all`) show up as edges back to an existing node.
   A derivation node keeps one rule application's premises together, so two
   derivations of the same fact stay distinct.")

(defn next-node-id
  "Returns a tuple of:
   ```clojure
     [node-id next-counter]
   ```
   Node ids are deterministic keywords (:n1, :n2, ...)."
  [counter]
  [(keyword (str "n" counter))
   (inc counter)])

(defn- unknown-explain
  "Describes the shape only: the explain may carry facts and bindings."
  [explain]
  (ex-info "Unknown explain node shape"
           {:node-keys  (when (map? explain) (set (keys explain)))
            :node-class (some-> explain class .getName)}))

(defn- new-node
  "Adds `node` under a fresh id and an edge to it from `from` (when given).
   Returns `[id state]`."
  [state from label node]
  (let [[id counter] (next-node-id (:counter state))]
    [id (cond-> (-> state
                    (assoc :counter counter)
                    (assoc-in [:nodes id] (assoc node :id id)))
          from (update :edges conj {:from from :to id :label label}))]))

(defn- check-children
  "The `[label item]` work items below a check node."
  [explain]
  (cond
    (= :pass (:result explain))
    (map (fn [f] [:because [:fact f]]) (:because explain))

    ;; failed reject check: the facts that matched are the evidence
    (contains? explain :rejected)
    (map (fn [f] [:rejected-by [:fact f]]) (:because explain))

    :else
    [[:missing [:missing (:missing explain)]]]))

(defn- check-node [explain]
  (cond-> {:kind     :check
           :check-id (:check-id explain)
           :result   (:result explain)}
    (contains? explain :block) (assoc :block (:block explain))))

(defn- policy-node [entry]
  (cond-> {:kind   :policy
           :index  (:index entry)
           :effect (:kind entry)
           :result (:result entry)}
    (:id entry) (assoc :policy-id (:id entry))))

(defn- push-children
  "Pushes `[label item]` pairs below node `id`, in reverse so they are
   visited in order."
  [stack id children]
  (into stack (map (fn [[label item]] [id label item])) (reverse children)))

(defn- walk
  "Depth-first over the fact table, iteratively (proof chains can be long).
   Each stack entry is `[from label [kind payload]]`; children are pushed
   in reverse so ids follow the explain's order."
  [state facts stack]
  (if-let [[from label [kind payload]] (peek stack)]
    (let [stack (pop stack)]
      (case kind
        :check
        (let [[id state] (new-node state from label (check-node payload))]
          (recur state facts (push-children stack id (check-children payload))))

        :policy
        (let [[id state] (new-node state from label (policy-node payload))]
          (recur state facts
                 (push-children stack id
                                (map (fn [f] [:because [:fact f]])
                                     (:because payload)))))

        :fact
        (if-let [id (get-in state [:seen payload])]
          (recur (update state :edges conj {:from from :to id :label label})
                 facts stack)
          (let [entry      (get facts payload)
                [id state] (new-node state from label
                                     {:kind    :fact
                                      :fact    payload
                                      :origin  (:origin entry)
                                      :stated? (boolean (:stated? entry))})]
            (recur (assoc-in state [:seen payload] id)
                   facts
                   (into stack
                         (map (fn [d] [id :derived-by [:derivation d]]))
                         (rseq (vec (:derivations entry)))))))

        :derivation
        (let [{:keys [rule block env proof]} payload
              [id state] (new-node state from label
                                   {:kind :derivation :rule rule
                                    :block block :env env})]
          (recur state facts
                 (into stack
                       (map (fn [f] [id :uses [:fact f]]))
                       (rseq (vec proof)))))

        :missing
        (let [[_ state] (new-node state from label
                                  {:kind :missing-fact :fact payload})]
          (recur state facts stack))))
    state))

(defn explain->graph
  "Converts an explain map — a decision or a single check — into a graph.

   The resulting graph contains:
   |||
   |:-|:-
   |`:root`  | root node id
   |`:nodes` | map of node-id -> node
   |`:edges` | list of directed edges with semantic labels."
  [explain]
  (let [etype (when (map? explain) (:type explain))
        state {:counter 1 :nodes {} :edges [] :seen {}}
        state (case etype
                :decision
                (let [[root state] (new-node state nil nil
                                             {:kind   :decision
                                              :result (:result explain)
                                              :reason (:reason explain)})]
                  (walk state (:facts explain)
                        (push-children []
                                       root
                                       (concat
                                        (map (fn [c] [:check [:check c]]) (:checks explain))
                                        (map (fn [p] [:policy [:policy p]]) (:policies explain))))))

                :check
                (walk state (:facts explain) [[nil nil [:check explain]]])

                (throw (unknown-explain explain)))]
    {:root  :n1
     :nodes (:nodes state)
     :edges (:edges state)}))
