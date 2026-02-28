(ns stroopwafel.datalog
  (:require
   [clojure.set :as set]
   [clojure.string :as str]))

(defn variable?
  "Returns true if the given value represents a logic variable.

   A variable is defined as a symbol whose name starts with '?'."
  [var]
  (and (symbol? var)
       (str/starts-with? (name var) "?")))

(defn bind
  "Attempts to bind a logic variable to a concrete value.

   If the variable is unbound, associates it with the given value.
   If the variable is already bound, ensures the existing binding
   matches the value.

   Returns the updated environment map if successful,
   or nil if the binding would cause a conflict."
  [env var value]
  (if-let [existing (get env var)]
    (when (= existing value) env)
    (assoc env var value)))

;;; ---- Fact store with origin tracking ----

(defn make-fact-store
  "Creates an empty fact store.

   A fact store maps facts to their origin sets:
     `{fact -> origin-set}`

   Origin model:
     - Authority facts: `#{0}`
     - Block N facts: `#{n}`
     - Authorizer facts: `#{:authorizer}`
     - Derived facts: union of input origins + rule block index"
  []
  {})

(defn insert-fact
  "Inserts a fact into the store with the given origin set.

   If the fact already exists, merges origin sets via union."
  [store fact origin]
  (update store fact (fn [existing]
                       (if existing
                         (set/union existing origin)
                         origin))))

(defn insert-facts
  "Inserts multiple facts into the store, all with the same origin set."
  [store facts origin]
  (reduce (fn [s f] (insert-fact s f origin)) store facts))

(defn fact-count
  "Returns the total number of unique facts in the store."
  [store]
  (count store))

;;; ---- Scope filtering ----

(defn trusted-origins
  "Returns the set of origin indices trusted by the given block.

   - Authority block (0): trusts `#{0 :authorizer}`
   - Block N: trusts `#{0 N :authorizer}`
   - Authorizer (nil): trusts `#{0 :authorizer}`"
  [block-index]
  (if (and block-index (pos? block-index))
    #{0 block-index :authorizer}
    #{0 :authorizer}))

(defn visible?
  "Returns true if a fact with the given origin set is visible
   to a block with the given trusted origin set.

   A fact is visible when its origin is a subset of trusted origins."
  [fact-origin trusted]
  (set/subset? fact-origin trusted))

(defn facts-for-scope
  "Returns a sequence of `[origin fact]` pairs visible in the given scope.

   Filters the store to only include facts whose origin sets are subsets
   of the trusted set."
  [store trusted]
  (for [[fact origin] store
        :when (visible? origin trusted)]
    [origin fact]))

(defn unify*
  "Pure structural pattern matching — no origin or proof tracking.

   Attempts to unify a pattern with a concrete fact given an
   accumulator state `{:env ... :proof ...}`.

   Returns updated state on success, nil on failure."
  [state pattern fact]
  (reduce (fn [state [pt ft]]
            (when state
              (let [{:keys [env proof]} state]
                (cond
                  (variable? pt)
                  (when-let [new-env (bind env pt ft)]
                    {:env   new-env
                     :proof proof})

                  (= pt ft)
                  state

                  :else nil))))
          state
          (map vector pattern fact)))

(defn unify
  "Attempts to unify a pattern with a concrete fact, producing
   variable bindings, proof metadata, and origin tracking.

   Accepts an optional `fact-origin` (default `#{0}`) which
   records where the matched fact came from.

   On success, returns a map with:
    |||
    |:-|:-|
    | `:env`    | variable bindings
    | `:proof`  | evidence showing which fact enabled the match
    | `:origin` | accumulated origin set

   On failure, returns `nil`."
  ([pattern fact]
   (unify pattern fact #{0}))
  ([pattern fact fact-origin]
   (when-let [result (unify* {:env {} :proof []} pattern fact)]
     (-> result
         (update :proof conj
                 {:type   :fact
                  :fact   fact
                  :origin fact-origin})
         (assoc :origin fact-origin)))))

(defn eval-body
  "Evaluates a rule or query body against a set of facts.

   The body is a sequence of patterns that must all be satisfied
   simultaneously (logical AND).

   `facts` can be either:
     - a sequence of bare facts (backward compatible)
     - a sequence of `[origin fact]` pairs (origin-aware)

   Returns a sequence of states, where each state contains:
   |||
   |:-|:-|
   | `:env`    | the combined variable bindings
   | `:proof`  | all facts that contributed to satisfying the body
   | `:origin` | accumulated origin set (union of matched fact origins)"
  [body facts]
  (let [;; Normalize: bare facts become [#{0} fact] pairs
        origin-facts (mapv (fn [f]
                             (if (and (vector? f) (= 2 (count f)) (set? (first f)))
                               f
                               [#{0} f]))
                           facts)]
    (reduce
     (fn [states pattern]
       (for [state states
             [fact-origin fact] origin-facts
             :let  [result (unify pattern fact fact-origin)]
             :when result
             :let  [merged-env    (merge (:env state) (:env result))
                    merged-proof  (into (:proof state) (:proof result))
                    merged-origin (set/union (or (:origin state) #{})
                                             (:origin result))]]
         {:env    merged-env
          :proof  merged-proof
          :origin merged-origin}))
     [{:env {} :proof [] :origin #{}}]
     body)))

(defn instantiate
  "Instantiates a rule head using a variable environment.

   Replaces all variables in the head with their bound values
   from the environment.

   If any variable in the head is unbound, returns nil."
  [head env]
  (let [result (mapv (fn [arg]
                       (cond
                         (variable? arg) (get env arg ::unbound)
                         :else arg))
                     head)]
    (when-not (some #{::unbound} result)
      result)))

(defn fire-rule
  "Applies a rule to a set of facts and produces derived facts
   along with full explanation metadata.

   Accepts either:
     - bare facts (backward compatible)
     - `[origin fact]` pairs with `rule-block-idx` for scoped derivation

   Derived fact origin = union of matched origins + rule block index.

   For each successful match of the rule body, generates a map with:
   |||
   |:-|:-|
   | `:fact`   | the derived fact
   | `:origin` | origin set (or :derived for legacy)
   | `:rule`   | the rule identifier
   | `:env`    | variable bindings used
   | `:proof`  | evidence from the rule body"
  ([rule facts]
   (fire-rule rule facts nil))
  ([{:keys [id head body]} facts rule-block-idx]
   (keep (fn [{:keys [env proof origin]}]
           (when-let [fact (instantiate head env)]
             {:fact   fact
              :origin (if rule-block-idx
                        (conj (or origin #{}) rule-block-idx)
                        :derived)
              :rule   id
              :env    env
              :proof  proof}))
         (eval-body body facts))))

(defn apply-rules
  "Applies rules to the final fact set and produces derived facts
   along with full explanation metadata. see: `fire-rule`"
  [rules facts]
  (mapcat #(fire-rule % (keys facts)) rules))

(def ^:private max-iterations
  "Maximum number of fixpoint iterations for rule application."
  100)

(def ^:private max-facts
  "Maximum total facts allowed in the store."
  1000)

(defn apply-rules-scoped
  "Applies rules per-block with scope filtering, running to fixpoint.

   `indexed-rules` is a sequence of `[block-index rules]` pairs.
   Rules in block N only see facts visible to block N.
   Derived facts get origin `(conj matched-origins block-index)`.

   Runs until no new facts are produced or limits are reached."
  [indexed-rules store]
  (loop [store store
         iteration 0]
    (if (>= iteration max-iterations)
      store
      (let [new-store
            (reduce
             (fn [acc [block-idx rules]]
               (let [trusted (trusted-origins block-idx)
                     visible (facts-for-scope acc trusted)]
                 (reduce
                  (fn [s rule]
                    (let [derived (fire-rule rule visible block-idx)]
                      (reduce (fn [s2 {:keys [fact origin]}]
                                (if (contains? s2 fact)
                                  s2
                                  (insert-fact s2 fact origin)))
                              s derived)))
                  acc rules)))
             store indexed-rules)]
        (if (or (= (fact-count new-store) (fact-count store))
                (>= (fact-count new-store) max-facts))
          new-store
          (recur new-store (inc iteration)))))))

(defn eval-check
  "Evaluates a single authorization check against the current fact store.

   If the check passes, returns a `:pass` result with an explanation
   rooted in the fact that satisfied the check.

   If the check fails, returns a `:fail` result with information about
   the missing required fact."
  [{:keys [id query]} fact-store]
  (let [results (eval-body query (keys fact-store))]
    (if (seq results)
      ;; pass
      (let [binding (first results)
            fact    (instantiate (first query) (:env binding))
            explain (get fact-store fact)]
        {:result  :pass
         :explain {:type     :check
                   :check-id id
                   :result   :pass
                   :because  explain}})

      ;; fail
      {:result  :fail
       :explain {:type     :check
                 :check-id id
                 :result   :fail
                 :missing  query}})))

(defn eval-checks
  "Evaluates all checks on the final fact set.

   Checks never produce new facts; they only validate conditions."
  [checks store]
  (map (fn [c] (eval-check c store)) checks))

(defn eval-token
  "Evaluates an authorization token consisting of one or more blocks.

   Each block may contribute facts, rules, and checks. The evaluation:
    1. Collects all facts
    2. Collects all rules
    2. Applies rules to derive new facts
    3. Evaluates all checks on the final facts [eval-checks]

   Returns a map with:
   |||
   |:-|:-|
   | `:valid?` | boolean authorization decision
   | `:explain` | optional proof tree when :explain? is enabled

   This is the main entry point for authorization decisions."
  [{:keys [blocks] :as _token} & {:keys [explain?]}]
  (let [all-facts (reduce (fn [st ft]
                            (assoc st ft {:origin :authority}))
                          {}
                          (mapcat :facts blocks))
        all-rules (into [] (mapcat :rules) blocks)
        derived (apply-rules all-rules all-facts)
        merged (reduce #(assoc %1 (:fact %2) %2) all-facts derived)
        results (eval-checks (mapcat :checks blocks) merged)
        failed (first (filter #(= :fail (:result %)) results))]
    (cond
      failed
      (as-> {:valid? false} m
        (when explain? (assoc m :explain (:explain failed))))

      :else
      (as-> {:valid? true} m
        (when explain? (assoc m :explain (:explain (last results))))))))
