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

   Pattern and fact must have the same arity; a mismatch never unifies.
   (Zipping alone would truncate to the shorter one and fail open.)

   Returns updated state on success, nil on failure."
  [state pattern fact]
  (when (= (count pattern) (count fact))
    (reduce (fn [state [pt ft]]
              (if-not state
                (reduced nil)
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
            (map vector pattern fact))))

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
   - All other values (numbers, strings, keywords) are returned as literals.

   Error data never includes `env`: bound values may be identifiers or
   secrets, and ex-data tends to end up in logs."
  [form env]
  (cond
    (variable? form)
    (let [v (get env form ::unbound)]
      (when (= v ::unbound)
        (throw (ex-info (str "Unbound variable in expression: " form)
                        {:variable form})))
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

(def default-limits
  "Fixpoint limits: `:max-iterations` rounds of rule application, and
   `:max-facts` facts in the store (input and derived)."
  {:max-iterations 100
   :max-facts      1000})

(defn validate-limits
  "Returns `limits` merged over `default-limits`; throws on unknown keys or
   values that aren't positive integers, so a typo can't silently keep
   (or drop) a limit."
  [limits]
  (let [unknown (remove (set (keys default-limits)) (keys limits))
        bad     (remove (fn [[_ v]] (pos-int? v)) limits)]
    (when (or (seq unknown) (seq bad))
      (throw (ex-info "Invalid limits: keys must be :max-iterations or :max-facts, values positive integers"
                      {:limits limits :unknown (vec unknown) :bad (into {} bad)})))
    (merge default-limits limits)))

(defn- limit-exceeded [limit limits store iterations]
  (ex-info (str "Fixpoint limit exceeded: " limit)
           {:stroopwafel/error :limit-exceeded
            :limit             limit
            :max               (get limits limit)
            :facts             (fact-count store)
            :iterations        iterations}))

(defn- derive-round
  "One round of the fixpoint: fires every block's rules in order, threading
   the store so later blocks see earlier blocks' facts from this round.
   A fact already in the store is never re-derived, so the first derivation
   found is the one kept. When `derivations` is a map (explain mode), each new
   fact's `{:rule :block :env :proof}` is recorded in it."
  [indexed-rules store derivations authorizer-scope]
  (reduce
   (fn [acc [block-idx rules]]
     (let [trusted (if (and (= block-idx :authorizer) authorizer-scope)
                     authorizer-scope
                     (trusted-origins block-idx))
           visible (facts-for-scope (:store acc) trusted)]
       (reduce
        (fn [acc rule]
          (reduce
           (fn [acc {:keys [fact origin env proof] rule-id :rule}]
             (if (contains? (:store acc) fact)
               acc
               (cond-> (update acc :store insert-fact fact origin)
                 (:derivations acc)
                 (assoc-in [:derivations fact] {:rule  rule-id
                                                :block block-idx
                                                :env   env
                                                :proof proof}))))
           acc
           (fire-rule rule visible block-idx)))
        acc rules)))
   {:store store :derivations derivations}
   indexed-rules))

(defn fixpoint
  "Applies rules per-block with scope filtering, running to fixpoint.
   Returns `{:store fact-store :derivations derivations}`.

   With `:explain? true`, `:derivations` maps each derived fact to the
   first derivation found — `{:rule :block :env :proof}` — so explain
   can show which rule produced it from which facts. Without it,
   `:derivations` is nil and nothing extra is kept.

   `indexed-rules` is a sequence of `[block-index rules]` pairs.
   Rules in block N only see facts visible to block N.
   Derived facts get origin `(conj matched-origins block-index)`.

   When `authorizer-scope` is provided, the `:authorizer` block uses
   that scope instead of the default `(trusted-origins :authorizer)`.
   This extends authorizer visibility to trusted third-party blocks.

   Runs until no new facts are produced. If a limit (`:limits`, over
   `default-limits`) is reached first, throws ex-info with
   `:stroopwafel/error :limit-exceeded`: a store cut short of its
   fixpoint lacks derived facts, and a `:reject` check or `:deny` policy
   over a missing fact would pass, so it must never be evaluated."
  [indexed-rules store & {:keys [authorizer-scope limits explain?]}]
  (let [{:keys [max-iterations max-facts] :as limits} (validate-limits limits)]
    (loop [store       store
           derivations (when explain? {})
           iteration   0]
      (let [{new-store :store derivations :derivations}
            (derive-round indexed-rules store derivations authorizer-scope)
            rounds (inc iteration)]
        (cond
          (= (fact-count new-store) (fact-count store))
          {:store new-store :derivations derivations}

          (> (fact-count new-store) max-facts)
          (throw (limit-exceeded :max-facts limits new-store rounds))

          (>= rounds max-iterations)
          (throw (limit-exceeded :max-iterations limits new-store rounds))

          :else
          (recur new-store derivations rounds))))))

(defn apply-rules-scoped
  "Like `fixpoint`, but returns only the resulting fact store.
   Takes the same `:authorizer-scope` and `:limits` options."
  [indexed-rules store & {:keys [authorizer-scope limits]}]
  (:store (fixpoint indexed-rules store
                    :authorizer-scope authorizer-scope
                    :limits limits)))

(defn- scope-visible-facts
  "Build scoped [origin fact] pairs. When scope is nil, uses all facts
   in the store."
  [fact-store scope]
  {:origin-facts (if scope
                   (facts-for-scope fact-store scope)
                   (into [] (map (fn [[fact origin]] [origin fact])) fact-store))})

(defn proof-nodes
  "Turns a match's `:proof` (the facts its body matched) into explain nodes.

   A stated fact is a leaf `{:fact :origin}`. A derived fact found in
   `derivations` (see `fixpoint`) becomes
   `{:fact :origin :rule :block :env :proof [child nodes]}`, expanded down to
   stated facts. Proofs only refer to facts that existed before the fact they
   prove, so expansion terminates; nodes are memoized, so a fact shared by
   several proof paths is built once and shared."
  [derivations proof]
  (let [memo (volatile! {})]
    (letfn [(node [{:keys [fact origin]}]
              (or (get @memo [fact origin])
                  (let [n (if-let [{:keys [rule block env proof]} (get derivations fact)]
                            {:fact   fact
                             :origin origin
                             :rule   rule
                             :block  block
                             :env    env
                             :proof  (mapv node proof)}
                            {:fact fact :origin origin})]
                    (vswap! memo assoc [fact origin] n)
                    n)))]
      (mapv node proof))))

(defn eval-check
  "Evaluates a single authorization check against a fact store.

   Accepts an optional `scope` (trusted origins set) to filter which
   facts are visible. When scope is nil, all facts in the store are used.

   Accepts an optional `explain?` flag. When true, realizes all matches
   and includes them in the explain output for audit/debug visibility.
   When false (default), uses early termination for performance.

   Accepts optional `derivations` (from `fixpoint` with `:explain? true`).
   A passing check's `:because`, and a failing reject check's, is a vector
   of `proof-nodes`, one per fact the body matched; derived facts expand
   to the rules that produced them. Without `derivations`, every node is
   a `{:fact :origin}` leaf.

   Supports `:kind`:
     - `:one` (default, check-if): passes if >= 1 match
     - `:reject` (reject-if / deny): passes if NO match"
  ([check fact-store]
   (eval-check check fact-store nil false))
  ([check fact-store scope]
   (eval-check check fact-store scope false))
  ([check fact-store scope explain?]
   (eval-check check fact-store scope explain? nil))
  ([{:keys [id query kind] guards :when} fact-store scope explain? derivations]
   (let [{:keys [origin-facts]} (scope-visible-facts fact-store scope)
         ;; Lazy seq — only realize what we need
         matches (cond->> (eval-body query origin-facts)
                   guards (filter (fn [{:keys [env]}] (eval-when guards env))))
         ;; In explain mode, realize all matches for audit visibility
         ;; Otherwise, early termination via first
         all-matches (when explain? (doall matches))
         first-match (if explain? (first all-matches) (first matches))
         reject? (= kind :reject)]
     (cond
       ;; reject-if: match means FAIL
       (and reject? first-match)
       {:result  :fail
        :explain {:type     :check
                  :check-id id
                  :result   :fail
                  :rejected query
                  :because  (proof-nodes derivations (:proof first-match))}}

       ;; reject-if: no match means PASS (nothing matched, so no evidence)
       (and reject? (nil? first-match))
       {:result  :pass
        :explain {:type     :check
                  :check-id id
                  :result   :pass
                  :because  []}}

       ;; check-if: match means PASS
       first-match
       {:result  :pass
        :explain (cond-> {:type     :check
                          :check-id id
                          :result   :pass
                          :because  (proof-nodes derivations (:proof first-match))}
                   ;; In explain mode, include all solutions
                   all-matches
                   (assoc :all-matches
                          (mapv (fn [{:keys [env origin]}]
                                  {:env env :origin origin
                                   :fact (instantiate (first query) env)})
                                all-matches)))}

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
  "Evaluates all checks on the fact store with optional scope filtering.
   When explain? is true, all matches are realized for audit visibility."
  ([checks store]
   (map (fn [c] (eval-check c store nil false)) checks))
  ([checks store scope]
   (map (fn [c] (eval-check c store scope false)) checks))
  ([checks store scope explain?]
   (eval-checks checks store scope explain? nil))
  ([checks store scope explain? derivations]
   (map (fn [c] (eval-check c store scope explain? derivations)) checks)))

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

   Accepts optional `:limits` (`:max-iterations`, `:max-facts`) over
   `default-limits`. Reaching a limit before the fixpoint denies.

   Returns:
   |||
   |:-|:-|
   | `:valid?`  | boolean authorization decision
   | `:explain` | optional proof tree when :explain? is enabled
   | `:error`   | when a limit was reached: `{:type :limit-exceeded :limit :max :facts :iterations}`"
  [{:keys [blocks] :as _token}
   & {:keys [explain? authorizer trusted-block-indices limits]}]
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

        ;; 4. Apply rules to fixpoint with scope filtering. A limit
        ;;    reached first denies: the partial store is never evaluated.
        {:keys [store derivations error]}
        (try
          (fixpoint indexed-rules store
                    :authorizer-scope authorizer-scope
                    :limits limits
                    :explain? explain?)
          (catch clojure.lang.ExceptionInfo e
            (let [data (ex-data e)]
              (if (= :limit-exceeded (:stroopwafel/error data))
                {:error (-> data
                            (dissoc :stroopwafel/error)
                            (assoc :type :limit-exceeded))}
                (throw e)))))]
    (if error
      (cond-> {:valid? false :error error}
        explain? (assoc :explain error))
      (let [;; 5. Evaluate checks per block with scoped visibility
            block-results
            (mapcat
             (fn [idx]
               (let [block (nth blocks idx)
                     scope (trusted-origins idx)]
                 (eval-checks (:checks block) store scope explain? derivations)))
             (range (count blocks)))

            ;; 6. Evaluate authorizer checks (with extended scope if trusted blocks)
            auth-scope (or authorizer-scope (trusted-origins nil))

            authorizer-results
            (when (:checks authorizer)
              (eval-checks (:checks authorizer) store auth-scope explain? derivations))

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
            {:valid? true}))))))
