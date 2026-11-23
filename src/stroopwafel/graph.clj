(ns stroopwafel.graph)

(defn next-node-id
  "Returns a tuple of:
   ```clojure
     [node-id next-counter]
   ```
   Node ids are deterministic keywords (:n1, :n2, ...)."
  [counter]
  [(keyword (str "n" counter))
   (inc counter)])

(defn check-node
  [id explain-node]
  {:id       id
   :kind     :check
   :check-id (:check-id explain-node)
   :result   (:result explain-node)})

(defn derived-fact-node
  [id explain-node]
  {:id     id
   :kind   :derived-fact
   :fact   (:fact explain-node)
   :origin (:origin explain-node)
   :rule   (:rule explain-node)
   :block  (:block explain-node)
   :env    (:env explain-node)})

(defn authority-fact-node
  [id explain-node]
  {:id     id
   :kind   :authority-fact
   :fact   (:fact explain-node)
   :origin (:origin explain-node)})

(defn missing-fact
  [id explain-node]
  {:id   id
   :kind :missing-fact
   :fact (:fact explain-node)})

(defn- derived-node?
  "Returns true if the explain node represents a derived fact.
   Derived facts are identified by the presence of a :rule key."
  [explain-node]
  (contains? explain-node :rule))

(defn explain-node->graph-node
  "Converts a single explain node into a graph node map.

   This function does not handle children; it only normalizes
   the current node into a graph-friendly representation.

   Origin format: sets (#{0}, #{0 1}, etc.) for facts."
  [id explain-node]
  (cond
    ;; check node
    (= (:type explain-node) :check) (check-node id explain-node)
    ;; derived fact (has :rule key)
    (derived-node? explain-node) (derived-fact-node id explain-node)
    ;; missing fact (synthetic)
    (= (:kind explain-node) :missing) (missing-fact id explain-node)
    ;; authority/block fact (origin is a set or keyword)
    (:origin explain-node) (authority-fact-node id explain-node)

    :else
    ;; Describe the shape only: the node itself may carry facts and bindings.
    (throw (ex-info "Unknown explain node shape"
                    {:node-keys  (when (map? explain-node)
                                   (set (keys explain-node)))
                     :node-class (some-> explain-node class .getName)}))))

(defn- because-nodes
  "A check's `:because`: a vector of proof nodes (what `evaluate` emits),
   or a single node (older hand-built trees)."
  [because]
  (cond (sequential? because) because
        (some? because)       [because]
        :else                 []))

(defn- children
  "The `[edge-label child-node]` pairs below an explain node."
  [explain-node]
  (cond
    (= (:type explain-node) :check)
    (cond
      (= :pass (:result explain-node))
      (map (fn [n] [:because n]) (because-nodes (:because explain-node)))

      ;; failed reject check: the facts that matched are the evidence
      (contains? explain-node :rejected)
      (map (fn [n] [:rejected-by n]) (because-nodes (:because explain-node)))

      :else
      [[:missing {:kind :missing :fact (:missing explain-node)}]])

    (derived-node? explain-node)
    (map (fn [n] [:because n]) (:proof explain-node))

    :else []))

(defn- fact-key
  "Facts are shared: the same fact reached along several proof paths is one
   node. Checks and synthetic missing-fact nodes are never shared."
  [explain-node]
  (when (and (map? explain-node)
             (contains? explain-node :fact)
             (not= :check (:type explain-node))
             (not= :missing (:kind explain-node)))
    (:fact explain-node)))

(defn- add-node
  "Adds `explain-node` and everything below it to graph state
   `{:counter :nodes :edges :seen}`, depth first. Returns `[id state]`."
  [state explain-node]
  (let [k (fact-key explain-node)]
    (if-let [id (and k (get-in state [:seen k]))]
      [id state]
      (let [[id counter] (next-node-id (:counter state))
            node         (explain-node->graph-node id explain-node)
            state        (cond-> (-> state
                                     (assoc :counter counter)
                                     (assoc-in [:nodes id] node))
                           k (assoc-in [:seen k] id))]
        (reduce (fn [[id state] [label child]]
                  (let [[child-id state] (add-node state child)]
                    [id (update state :edges conj
                                {:from id :to child-id :label label})]))
                [id state]
                (children explain-node))))))

(defn build-graph
  "Converts an explain tree into a graph fragment, numbering nodes from
   `counter`. A fact reached along several proof paths becomes one node
   with several incoming edges.

   Returns a tuple:
     ```clojure
     [node-id next-counter {:nodes {...} :edges [...]}]
   ```"
  [explain-node counter]
  (let [[id state] (add-node {:counter counter :nodes {} :edges [] :seen {}}
                             explain-node)]
    [id (:counter state) (select-keys state [:nodes :edges])]))

(defn explain->graph
  "Converts an explain tree produced by the core into a graph structure.

   The resulting graph contains:
   |||
   |:-|:-
   |`:root`  | root node id
   |`:nodes` | map of node-id -> node
   |`:edges` | list of directed edges with semantic labels."
  [explain]
  (let [[root-id _ graph] (build-graph explain 1)]
    (assoc graph :root root-id)))
