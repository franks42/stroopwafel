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

(defn value=
  "Value equality that handles byte arrays.

   Clojure's = compares byte arrays by identity, not content.
   This function uses java.util.Arrays/equals for byte arrays
   and falls back to = for everything else."
  [a b]
  (if (and (bytes? a) (bytes? b))
    (java.util.Arrays/equals ^bytes a ^bytes b)
    (= a b)))

(defn bind
  "Attempts to bind a logic variable to a concrete value.

   If the variable is unbound, associates it with the given value.
   If the variable is already bound, ensures the existing binding
   matches the value (using value= for byte-array-aware comparison).

   Returns the updated environment map if successful,
   or nil if the binding would cause a conflict."
  [env var value]
  (if-let [existing (get env var)]
    (when (value= existing value) env)
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
   - Block N (positive int): trusts `#{0 N :authorizer}`
   - Authorizer (nil or :authorizer): trusts `#{0 :authorizer}`"
  [block-index]
  (if (and (number? block-index) (pos? block-index))
    #{0 block-index :authorizer}
    #{0 :authorizer}))

(defn visible?
  "Returns true if a fact with the given origin set is visible
   to a block with the given trusted origin set.

   A fact is visible when its origin is a subset of trusted origins."
  [fact-origin trusted]
  (set/subset? fact-origin trusted))

(defn facts-for-scope
  "Returns a vector of `[origin fact]` pairs visible in the given scope.

   Filters the store to only include facts whose origin sets are subsets
   of the trusted set. Uses transducer to avoid intermediate seq allocation."
  [store trusted]
  (into []
        (keep (fn [[fact origin]]
                (when (visible? origin trusted)
                  [origin fact])))
        store))

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

                  (value= pt ft)
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
   (unify pattern fact fact-origin {}))
  ([pattern fact fact-origin env]
   (when-let [result (unify* {:env env :proof []} pattern fact)]
     (-> result
         (update :proof conj
                 {:type   :fact
                  :fact   fact
                  :origin fact-origin})
         (assoc :origin fact-origin)))))

(defn- normalize-facts
  "Normalize facts: bare facts become [#{0} fact] pairs.
   Already-normalized pairs (vector of [set fact]) pass through."
  [facts]
  (into []
        (map (fn [f]
               (if (and (vector? f) (= 2 (count f)) (set? (first f)))
                 f
                 [#{0} f])))
        facts))

(defn eval-body
  "Evaluates a rule or query body against a set of facts.

   The body is a sequence of patterns that must all be satisfied
   simultaneously (logical AND).

   `facts` can be either:
     - a sequence of bare facts (backward compatible)
     - a sequence of `[origin fact]` pairs (origin-aware)

   Returns a lazy sequence of states, where each state contains:
   |||
   |:-|:-|
   | `:env`    | the combined variable bindings
   | `:proof`  | all facts that contributed to satisfying the body
   | `:origin` | accumulated origin set (union of matched fact origins)"
  [body facts]
  (let [origin-facts (normalize-facts facts)]
    (reduce
     (fn [states pattern]
       (for [state states
             [fact-origin fact] origin-facts
             :let  [result (unify pattern fact fact-origin (:env state))]
             :when result
             :let  [merged-proof  (into (:proof state) (:proof result))
                    merged-origin (set/union (or (:origin state) #{})
                                             (:origin result))]]
         {:env    (:env result)
          :proof  merged-proof
          :origin merged-origin}))
     [{:env {} :proof [] :origin #{}}]
     body)))

;;; ---- Expression evaluator ----

(def built-in-fns
  "Whitelisted functions for :when guard expressions.

   Security-critical: only registered functions can be called. No eval,
   no resolve, no namespace lookup, no I/O. String functions use the
   str/ prefix matching clojure.string namespace."
  {;; Comparison
   '<          <
   '>          >
   '<=         <=
   '>=         >=
   '=          =
   'not=       not=
   ;; Arithmetic
   '+          +
   '-          -
   '*          *
   '/          /
   'mod        mod
   'rem        rem
   ;; String
   'str/starts-with?  str/starts-with?
   'str/ends-with?    str/ends-with?
   'str/includes?     str/includes?
   'str/lower-case    str/lower-case
   'str/upper-case    str/upper-case
   'subs              subs
   'str               str
   ;; Logic
   'not        not
   'and        (fn [& args] (every? identity args))
   'or         (fn [& args] (some identity args))
   ;; Collections
   'contains?  contains?
   'empty?     empty?
   'count      count
   ;; Type predicates
   'string?    string?
   'number?    number?
   'keyword?   keyword?
   'int?       int?
   'nil?       nil?
   'some?      some?
   ;; Regex
   're-matches re-matches
   're-find    re-find})

(defn eval-expr
  "Evaluates a single expression form in the given variable environment.

   - Variables (`?`-prefixed symbols) are looked up in `env`; throws if unbound.
   - Sequential forms `(f arg1 arg2 ...)` resolve `f` from `built-in-fns`,
     recursively evaluate args, then apply.
   - All other values (numbers, strings, keywords) are returned as literals."
  [form env]
  (cond
    (variable? form)
    (let [v (get env form ::unbound)]
      (when (= v ::unbound)
        (throw (ex-info (str "Unbound variable in expression: " form)
                        {:variable form :env env})))
      v)

    (sequential? form)
    (let [[op & args] form
          f (get built-in-fns op)]
      (when-not f
        (throw (ex-info (str "Unknown function in expression: " op)
                        {:function op})))
      (apply f (map #(eval-expr % env) args)))

    :else form))

(defn eval-let
  "Evaluates `:let` bindings, extending the environment with computed variables.

   Each binding is `[?var expr]`. Bindings are evaluated sequentially — later
   bindings can reference earlier ones. Returns the extended env.
   Returns env unchanged when `let-bindings` is nil or empty."
  [let-bindings env]
  (if (seq let-bindings)
    (reduce (fn [env [var expr]]
              (assoc env var (eval-expr expr env)))
            env let-bindings)
    env))

(defn eval-when
  "Evaluates `:when` guard clauses against a variable environment.

   All clauses must return truthy. Returns true when `when-clauses` is
   nil or empty (backward compatible — no guards means always passes)."
  [when-clauses env]
  (if (seq when-clauses)
    (every? #(eval-expr % env) when-clauses)
    true))

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
  ([{:keys [id head body] guards :when let-bindings :let} facts rule-block-idx]
   (keep (fn [{:keys [env proof origin]}]
           (let [env (eval-let let-bindings env)]
             (when (eval-when guards env)
               (when-let [fact (instantiate head env)]
                 {:fact   fact
                  :origin (if rule-block-idx
                            (conj (or origin #{}) rule-block-idx)
                            :derived)
                  :rule   id
                  :env    env
                  :proof  proof}))))
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

   When `authorizer-scope` is provided, the `:authorizer` block uses
   that scope instead of the default `(trusted-origins :authorizer)`.
   This extends authorizer visibility to trusted third-party blocks.

   Runs until no new facts are produced or limits are reached.
   Uses transduce over derived facts to avoid materializing
   intermediate sequences."
  [indexed-rules store & {:keys [authorizer-scope]}]
  (loop [store store
         iteration 0]
    (if (>= iteration max-iterations)
      store
      (let [new-store
            (reduce
             (fn [acc [block-idx rules]]
               (let [trusted (if (and (= block-idx :authorizer) authorizer-scope)
                               authorizer-scope
                               (trusted-origins block-idx))
                     visible (facts-for-scope acc trusted)]
                 (reduce
                  (fn [s rule]
                    (transduce
                     (keep (fn [{:keys [fact origin]}]
                             (when-not (contains? s fact)
                               [fact origin])))
                     (completing
                      (fn [s2 [fact origin]]
                        (insert-fact s2 fact origin)))
                     s
                     (fire-rule rule visible block-idx)))
                  acc rules)))
             store indexed-rules)]
        (if (or (= (fact-count new-store) (fact-count store))
                (>= (fact-count new-store) max-facts))
          new-store
          (recur new-store (inc iteration)))))))

(defn- scope-visible-facts
  "Build scoped [origin fact] pairs and a fact→origin lookup map.
   When scope is nil, uses all facts in the store."
  [fact-store scope]
  (if scope
    (let [pairs (facts-for-scope fact-store scope)]
      {:origin-facts pairs
       :fact-lookup  (into {} (map (fn [[origin fact]] [fact origin])) pairs)})
    {:origin-facts (into [] (map (fn [[fact origin]] [origin fact])) fact-store)
     :fact-lookup  fact-store}))

(defn eval-check
  "Evaluates a single authorization check against a fact store.

   Accepts an optional `scope` (trusted origins set) to filter which
   facts are visible. When scope is nil, all facts in the store are used.

   Supports `:kind`:
     - `:one` (default, check-if): passes if >= 1 match
     - `:reject` (reject-if / deny): passes if NO match

   Uses early termination: for check-if, stops at first match.
   For reject-if, stops at first match (which means failure)."
  ([check fact-store]
   (eval-check check fact-store nil))
  ([{:keys [id query kind] guards :when} fact-store scope]
   (let [{:keys [origin-facts fact-lookup]} (scope-visible-facts fact-store scope)
         ;; Lazy seq — only realize what we need
         matches (cond->> (eval-body query origin-facts)
                   guards (filter (fn [{:keys [env]}] (eval-when guards env))))
         ;; Early termination: just check first match
         first-match (first matches)
         reject? (= kind :reject)]
     (cond
       ;; reject-if: match means FAIL
       (and reject? first-match)
       {:result  :fail
        :explain {:type     :check
                  :check-id id
                  :result   :fail
                  :rejected query}}

       ;; reject-if: no match means PASS
       (and reject? (nil? first-match))
       {:result  :pass
        :explain {:type     :check
                  :check-id id
                  :result   :pass
                  :because  {:origin :reject-pass}}}

       ;; check-if: match means PASS
       first-match
       (let [fact    (instantiate (first query) (:env first-match))
             explain (get fact-lookup fact)]
         {:result  :pass
          :explain {:type     :check
                    :check-id id
                    :result   :pass
                    :because  (or explain {:origin (:origin first-match)
                                           :fact   fact})}})

       ;; check-if: no match means FAIL
       :else
       {:result  :fail
        :explain {:type     :check
                  :check-id id
                  :result   :fail
                  :missing  query}}))))

(defn eval-policy
  "Evaluates a single authorizer policy against a fact store with scope.

   A policy has:
     - `:kind` — `:allow` or `:deny`
     - `:query` — fact patterns to match

   Returns:
     - `{:matched? true :kind :allow/:deny}` if the query matches
     - `{:matched? false}` if the query does not match

   Uses early termination — stops at first match."
  [{:keys [kind query] guards :when} fact-store scope]
  (let [{:keys [origin-facts]} (scope-visible-facts fact-store scope)
        matches (cond->> (eval-body query origin-facts)
                  guards (filter (fn [{:keys [env]}] (eval-when guards env))))]
    (if (first matches)
      {:matched? true :kind kind}
      {:matched? false})))

(defn eval-policies
  "Evaluates authorizer policies in order. First matching policy wins.

   - `:allow` match → `{:result :allow}`
   - `:deny` match → `{:result :deny}`
   - No match → `{:result :deny}` (closed-world default)

   Policies are only evaluated after all block checks pass."
  [policies fact-store scope]
  (if (empty? policies)
    {:result :allow}
    (let [first-match (some (fn [policy]
                              (let [r (eval-policy policy fact-store scope)]
                                (when (:matched? r) r)))
                            policies)]
      (if first-match
        {:result (:kind first-match)}
        {:result :deny}))))

(defn eval-checks
  "Evaluates all checks on the fact store with optional scope filtering."
  ([checks store]
   (map (fn [c] (eval-check c store)) checks))
  ([checks store scope]
   (map (fn [c] (eval-check c store scope)) checks)))

(defn eval-token
  "Evaluates an authorization token with per-block scope isolation.

   Each block's facts are tagged with their block index as origin.
   Rules fire with scope filtering — a rule in block N only sees
   authority facts (#{0}), its own block facts (#{N}), and authorizer
   facts (#{:authorizer}).

   Checks are evaluated per-block with appropriate scope:
     - Block 0 checks: scope #{0 :authorizer}
     - Block N checks: scope #{0 N :authorizer}
     - Authorizer checks: scope #{0 :authorizer}

   Accepts optional `:authorizer` map with:
     - `:facts`  — additional authorizer facts
     - `:checks` — additional authorizer checks
     - `:rules`  — additional authorizer rules

   Returns:
   |||
   |:-|:-|
   | `:valid?`  | boolean authorization decision
   | `:explain` | optional proof tree when :explain? is enabled"
  [{:keys [blocks] :as _token}
   & {:keys [explain? authorizer trusted-block-indices]}]
  (let [;; Compute authorizer scope (extended when third-party blocks are trusted)
        authorizer-scope (when trusted-block-indices
                           (into #{0 :authorizer} trusted-block-indices))

        ;; 1. Build fact store with origin tags
        store (reduce-kv
               (fn [s idx block]
                 (insert-facts s (:facts block) #{idx}))
               (make-fact-store)
               (vec blocks))

        ;; 2. Add authorizer facts
        store (if (:facts authorizer)
                (insert-facts store (:facts authorizer) #{:authorizer})
                store)

        ;; 3. Index rules by block
        indexed-rules
        (into []
              (concat
               (map-indexed (fn [idx block] [idx (:rules block)]) blocks)
               (when (:rules authorizer)
                 [[:authorizer (:rules authorizer)]])))

        ;; 4. Apply rules to fixpoint with scope filtering
        store (apply-rules-scoped indexed-rules store
                                  :authorizer-scope authorizer-scope)

        ;; 5. Evaluate checks per block with scoped visibility
        block-results
        (mapcat
         (fn [idx]
           (let [block (nth blocks idx)
                 scope (trusted-origins idx)]
             (eval-checks (:checks block) store scope)))
         (range (count blocks)))

        ;; 6. Evaluate authorizer checks (with extended scope if trusted blocks)
        auth-scope (or authorizer-scope (trusted-origins nil))

        authorizer-results
        (when (:checks authorizer)
          (eval-checks (:checks authorizer) store auth-scope))

        all-results (concat block-results authorizer-results)
        failed (first (filter #(= :fail (:result %)) all-results))

        ;; 7. Evaluate authorizer policies (after all checks pass)
        policy-result
        (when (and (nil? failed) (:policies authorizer))
          (eval-policies (:policies authorizer) store auth-scope))]
    (cond
      failed
      (if explain?
        {:valid? false :explain (:explain failed)}
        {:valid? false})

      (and policy-result (= :deny (:result policy-result)))
      (if explain?
        {:valid? false :explain {:type :policy :result :deny}}
        {:valid? false})

      :else
      (if explain?
        {:valid? true :explain (:explain (last all-results))}
        {:valid? true}))))
