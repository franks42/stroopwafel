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

   A fact store maps each fact to the set of origin sets it was found with:
     `{fact -> #{origin-set ...}}`

   Origin model:
     - Authority facts: `#{0}`
     - Block N facts: `#{n}`
     - Authorizer facts: `#{:authorizer}`
     - Derived facts: union of input origins + rule block index

   A fact can hold several origin sets, because it can be stated or derived
   in more than one way, and each way is visible to different scopes. A
   scope sees the fact if _any_ of its origin sets is visible. Keeping only
   one (the first found, or a union) would let an appended block hide a fact
   from the authorizer — and a hidden fact behind a reject check or deny
   policy fails open."
  []
  {})

(defn adds-origin?
  "True when inserting `fact` with `origin` would make it visible somewhere
   it isn't yet: no origin set already kept for it is a subset of `origin`."
  [store fact origin]
  (not-any? #(set/subset? % origin) (get store fact)))

(defn insert-fact
  "Inserts a fact into the store with the given origin set.

   Keeps only minimal origin sets: visibility is `subset?`, so an origin set
   that contains a kept one adds no visibility and is dropped, and kept
   supersets of a new origin set are replaced by it. Never unions origins.
   Returns `store` itself when nothing changes."
  [store fact origin]
  (if (adds-origin? store fact origin)
    (assoc store fact (conj (into #{} (remove #(set/subset? origin %)) (get store fact))
                            origin))
    store))

(defn insert-facts
  "Inserts multiple facts into the store, all with the same origin set."
  [store facts origin]
  (reduce (fn [s f] (insert-fact s f origin)) store facts))

(defn fact-count
  "Returns the total number of unique facts in the store."
  [store]
  (count store))

(defn origin-count
  "Returns the number of (fact, origin set) entries in the store. The
   fixpoint is reached when a round adds none."
  [store]
  (reduce-kv (fn [n _ origins] (+ n (count origins))) 0 store))

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
  "Returns a vector of `[origin fact]` pairs visible in the given scope:
   one pair per origin set of a fact that is a subset of `trusted`. A fact
   visible through two incomparable origin sets appears twice, since a
   derivation from it carries whichever origin it used."
  [store trusted]
  (into []
        (mapcat (fn [[fact origins]]
                  (keep (fn [origin]
                          (when (visible? origin trusted)
                            [origin fact]))
                        origins)))
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

(defn- fact-source
  "Wraps `[origin fact]` pairs for `join`, with a lazily built index by
   predicate and length."
  [pairs]
  {:pairs pairs
   :index (delay (group-by (fn [[_ fact]] [(first fact) (count fact)]) pairs))})

(defn- candidates
  "The pairs of `src` that `pattern` can unify with: those with the same
   predicate and length, when the predicate is a constant that compares by
   `=`. A variable or byte-array predicate scans every pair."
  [src pattern]
  (let [pred (first pattern)]
    (if (or (variable? pred) (bytes? pred))
      (:pairs src)
      (get @(:index src) [pred (count pattern)]))))

(defn- join
  "Matches `body` pattern by pattern, pattern i against the pairs of the i-th
   of `sources` (see `fact-source`). Returns a lazy sequence of `{:env :proof
   :origin}` states, as `eval-body` describes."
  [body sources]
  (reduce
   (fn [states [pattern src]]
     (for [state states
           [fact-origin fact] (candidates src pattern)
           :let  [result (unify pattern fact fact-origin (:env state))]
           :when result]
       {:env    (:env result)
        :proof  (into (:proof state) (:proof result))
        :origin (set/union (:origin state) (:origin result))}))
   [{:env {} :proof [] :origin #{}}]
   (map vector body sources)))

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
  (let [src (fact-source (normalize-facts facts))]
    (join body (repeat src))))

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

(defn- fire-states
  "The derivations of `rule` from body-match `states` (see `fire-rule`)."
  [{:keys [id head] guards :when let-bindings :let} states rule-block-idx]
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
        states))

(defn- delta-states
  "Semi-naive body matches of `rule`: those using at least one pair from
   `delta`, each found once. Pass i matches pattern i against `delta`,
   earlier patterns against `old` (pairs not in delta) and later ones against
   `full`. A rule with an empty body has no delta matches; it fired in its
   block's first, full pass."
  [{:keys [body]} old delta full]
  (let [n (count body)]
    (mapcat (fn [i]
              (join body (concat (repeat i old) [delta] (repeat (- n i 1) full))))
            (range n))))

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
  ([rule facts rule-block-idx]
   (fire-states rule (eval-body (:body rule) facts) rule-block-idx)))

(defn apply-rules
  "Applies rules to the final fact set and produces derived facts
   along with full explanation metadata. see: `fire-rule`"
  [rules facts]
  (mapcat #(fire-rule % (keys facts)) rules))

(def default-limits
  "Fixpoint limits: `:max-iterations` rounds of rule application, and
   `:max-facts` entries in the store (input and derived), where a fact
   counts once per origin set it holds. Reaching either
   denies.

   `:max-derivations` caps how many derivations explain records. It only
   bounds explain data: reaching it stops recording and flags the explain
   `:truncated? true`, but never changes the decision."
  {:max-iterations  100
   :max-facts       1000
   :max-derivations 10000})

(defn validate-limits
  "Returns `limits` merged over `default-limits`; throws on unknown keys or
   values that aren't positive integers, so a typo can't silently keep
   (or drop) a limit."
  [limits]
  (let [unknown (remove (set (keys default-limits)) (keys limits))
        bad     (remove (fn [[_ v]] (pos-int? v)) limits)]
    (when (or (seq unknown) (seq bad))
      (throw (ex-info "Invalid limits: keys must be :max-iterations, :max-facts or :max-derivations, values positive integers"
                      {:limits limits :unknown (vec unknown) :bad (into {} bad)})))
    (merge default-limits limits)))

(defn- limit-exceeded [limit limits store iterations]
  (ex-info (str "Fixpoint limit exceeded: " limit)
           {:stroopwafel/error :limit-exceeded
            :limit             limit
            :max               (get limits limit)
            :facts             (origin-count store)
            :iterations        iterations}))

(defn- record-derivation
  "Adds derivation `d` of `fact` to explain state `ex`
   `{:derivations :count :max :truncated?}` unless already recorded or the
   cap is reached (which flags `:truncated?`)."
  [ex fact d]
  (let [ds (get-in ex [:derivations fact] [])]
    (cond
      (some #{d} ds)          ex
      (>= (:count ex) (:max ex)) (assoc ex :truncated? true)
      :else                   (-> ex
                                  (assoc-in [:derivations fact] (conj ds d))
                                  (update :count inc)))))

(defn- block-states
  "Body matches for each of `rules` in one block's turn, as `[rule states]`.

   `pos` is where the insertion `log` stood at this block's previous turn
   (nil on its first turn). The first turn matches every rule against every
   visible pair. Later turns are semi-naive: only matches that use a pair
   inserted since `pos` and still kept (`delta`) — any other match was
   already found in an earlier turn. With no delta the block derives nothing
   new and is skipped."
  [rules store log pos trusted]
  (let [visible (facts-for-scope store trusted)]
    (if (nil? pos)
      (let [full (fact-source visible)]
        (map (fn [rule] [rule (join (:body rule) (repeat full))]) rules))
      (let [delta (filterv (fn [[origin fact]]
                             (and (visible? origin trusted)
                                  (contains? (get store fact) origin)))
                           (subvec log pos))]
        (when (seq delta)
          (let [in-delta (set delta)
                old      (fact-source (into [] (remove in-delta) visible))
                new      (fact-source delta)
                full     (fact-source visible)]
            (map (fn [rule] [rule (delta-states rule old new full)]) rules)))))))

(defn- derive-round
  "One round of the fixpoint: each block's turn in order, then the
   authorizer's, threading the store so later blocks see earlier blocks'
   facts from this round. A turn sees the store as it was when the turn
   began. A derivation is inserted only when it adds an origin set (see
   `insert-fact`), so the same fact can be found again with an origin that
   makes it visible to more scopes.

   Evaluation is semi-naive (see `block-states`): `log` records every
   inserted `[origin fact]` pair and `pos` where it stood at each block's
   last turn (keyed by the block's position in `indexed-rules`). Each round
   derives exactly what re-firing every rule over every visible fact would.

   `ex` is explain state (nil when explain is off). In `:first` mode it
   records each derivation that added an origin set. In `:all` mode it
   records every distinct derivation, including of facts already in the
   store; each match of a rule body is found in some turn, so over all
   rounds that is every derivation."
  [indexed-rules state authorizer-scope]
  (reduce
   (fn [acc [k [block-idx rules]]]
     (let [trusted (if (and (= block-idx :authorizer) authorizer-scope)
                     authorizer-scope
                     (trusted-origins block-idx))
           log     (:log acc)
           matches (block-states rules (:store acc) log (get-in acc [:pos k]) trusted)]
       (reduce
        (fn [acc [rule states]]
          (reduce
           (fn [acc {:keys [fact origin env proof] rule-id :rule}]
             (let [new? (adds-origin? (:store acc) fact origin)
                   ex   (:ex acc)]
               (cond-> acc
                 new?
                 (-> (update :store insert-fact fact origin)
                     (update :log conj [origin fact]))

                 (and ex (or new? (= :all (:mode ex))))
                 (update :ex record-derivation fact
                         {:rule   rule-id
                          :block  block-idx
                          :origin origin
                          :env    env
                          :proof  (mapv :fact proof)}))))
           acc
           (fire-states rule states block-idx)))
        (assoc-in acc [:pos k] (count log))
        matches)))
   state
   (map-indexed vector indexed-rules)))

(defn fixpoint
  "Applies rules per-block with scope filtering, running to fixpoint.
   Returns `{:store fact-store :derivations derivations :truncated? bool}`.

   `:derivations` maps a fact to a vector of `{:rule :block :origin :env
   :proof}`, where `:origin` is the origin set the derivation produced and
   `:proof` is the facts the rule body matched. With `:explain? true` it
   holds the first derivation for each origin set the fact gained; with
   `:explain? :all`, every distinct derivation of every fact — circular
   ones included. Recording stops at `:max-derivations` (see
   `default-limits`) and sets `:truncated?`. Without `:explain?`,
   `:derivations` is nil and nothing extra is kept.

   `indexed-rules` is a sequence of `[block-index rules]` pairs.
   Rules in block N only see facts visible to block N.
   Derived facts get origin `(conj matched-origins block-index)`.

   When `authorizer-scope` is provided, the `:authorizer` block uses
   that scope instead of the default `(trusted-origins :authorizer)`.
   This extends authorizer visibility to trusted third-party blocks.

   Runs until a round leaves the store unchanged — not merely its size: a
   smaller origin set replacing a kept superset makes a fact visible to more
   scopes without changing the count. If a limit (`:limits`, over
   `default-limits`) is reached first, throws ex-info with
   `:stroopwafel/error :limit-exceeded`: a store cut short of its
   fixpoint lacks derived facts, and a `:reject` check or `:deny` policy
   over a missing fact would pass, so it must never be evaluated."
  [indexed-rules store & {:keys [authorizer-scope limits explain?]}]
  (let [{:keys [max-iterations max-facts] :as limits} (validate-limits limits)]
    (loop [{:keys [store] :as state}
           {:store store
            :log   []
            :pos   {}
            :ex    (when explain?
                     {:mode        (if (= :all explain?) :all :first)
                      :derivations {}
                      :count       0
                      :max         (:max-derivations limits)})}
           iteration 0]
      (let [{new-store :store ex :ex :as state}
            (derive-round indexed-rules state authorizer-scope)
            rounds (inc iteration)]
        (cond
          ;; Not a count comparison: a smaller origin set replacing a kept
          ;; superset leaves the count unchanged but makes the fact visible
          ;; to more scopes, which may then derive more. `insert-fact`
          ;; returns the store itself when nothing changes.
          (identical? new-store store)
          (cond-> {:store new-store :derivations (:derivations ex)}
            (:truncated? ex) (assoc :truncated? true))

          (> (origin-count new-store) max-facts)
          (throw (limit-exceeded :max-facts limits new-store rounds))

          (>= rounds max-iterations)
          (throw (limit-exceeded :max-iterations limits new-store rounds))

          :else
          (recur state rounds))))))

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
                   (into [] (mapcat (fn [[fact origins]]
                                      (map (fn [o] [o fact]) origins)))
                         fact-store))})

(defn explain-facts
  "The explain fact table for `roots`: every fact reachable from them
   through derivation proofs, each once, as
   `{fact {:origins #{o …} :stated? true
           :derivations [{:rule :block :origin :env :proof}]}}`.
   `:origins` are the minimal origin sets the fact was found with.
   `:stated?` is present when a block or the authorizer stated the fact;
   `:derivations` when a rule derived it. Proofs may refer back to facts
   already in the table — that is how circular derivations appear."
  [roots fact-store derivations stated]
  (loop [todo  (vec roots)
         table {}]
    (if-let [fact (peek todo)]
      (if (contains? table fact)
        (recur (pop todo) table)
        (let [ds    (get derivations fact)
              entry (cond-> {:origins (get fact-store fact)}
                      (contains? stated fact) (assoc :stated? true)
                      (seq ds)                (assoc :derivations ds))]
          (recur (into (pop todo) (mapcat :proof) ds)
                 (assoc table fact entry))))
      table)))

(defn- query-matches
  "Lazy seq of matches of `query` (with `:when` `guards`) over the facts
   visible in `scope`."
  [query guards fact-store scope]
  (let [{:keys [origin-facts]} (scope-visible-facts fact-store scope)]
    (cond->> (eval-body query origin-facts)
      guards (filter (fn [{:keys [env]}] (eval-when guards env))))))

(defn- match-evidence
  "Adds the evidence for a match to an explain map: `:because` (the facts
   of the first match, or of every match in `:all` mode), `:matches` (every
   match, when realized), and — given an explain context — `:facts`, the
   fact table for `:because`."
  [explain first-match all-matches fact-store ctx]
  (let [because (if (= :all (:mode ctx))
                  (into [] (comp (mapcat #(map :fact (:proof %))) (distinct))
                        all-matches)
                  (mapv :fact (:proof first-match)))]
    (cond-> (assoc explain :because because)
      all-matches
      (assoc :matches (mapv (fn [{:keys [env origin proof]}]
                              {:env env :origin origin
                               :facts (mapv :fact proof)})
                            all-matches))
      ctx
      (assoc :facts (explain-facts because fact-store
                                   (:derivations ctx) (:stated ctx)))
      (:truncated? ctx)
      (assoc :truncated? true))))

(defn eval-check
  "Evaluates a single authorization check against a fact store.

   Accepts an optional `scope` (trusted origins set) to filter which
   facts are visible. When scope is nil, all facts in the store are used.

   Accepts an optional `explain?` flag. When true, realizes all matches
   and includes them in the explain output for audit/debug visibility.
   When false (default), uses early termination for performance.

   Accepts an optional explain context `ctx` (see `eval-token`):
   `{:mode :first|:all :derivations {…} :stated store :truncated? bool}`.
   When a check passes, or a reject check fails, the explain carries:
     - `:because` — the matched facts: of the first match in `:first` mode,
       of every match in `:all` mode;
     - `:matches` — every match as `{:env :origin :facts}` (explain only);
     - `:facts`   — the fact table for `:because` (see `explain-facts`).

   Supports `:kind`:
     - `:one` (default, check-if): passes if >= 1 match
     - `:reject` (reject-if / deny): passes if NO match"
  ([check fact-store]
   (eval-check check fact-store nil false))
  ([check fact-store scope]
   (eval-check check fact-store scope false))
  ([check fact-store scope explain?]
   (eval-check check fact-store scope explain? nil))
  ([{:keys [id query kind] guards :when} fact-store scope explain? ctx]
   (let [;; Lazy seq — only realize what we need
         matches (query-matches query guards fact-store scope)
         ;; In explain mode, realize all matches for audit visibility
         ;; Otherwise, early termination via first
         all-matches (when explain? (doall matches))
         first-match (if explain? (first all-matches) (first matches))
         reject? (= kind :reject)
         evidence #(match-evidence % first-match all-matches fact-store ctx)]
     (cond
       ;; reject-if: match means FAIL
       (and reject? first-match)
       {:result  :fail
        :explain (evidence {:type     :check
                            :check-id id
                            :result   :fail
                            :rejected query})}

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
        :explain (evidence {:type     :check
                            :check-id id
                            :result   :pass})}

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
     - `:when` — optional guards
     - `:id` — optional, reported in explain

   Returns `{:matched? bool :kind kind :explain entry}`, where `entry` is
   `{:id :kind :query :result :matched|:no-match}`; with `explain?`, a
   matched entry also carries the evidence (see `eval-check`).

   Without `explain?`, stops at the first match."
  ([policy fact-store scope]
   (eval-policy policy fact-store scope false nil))
  ([{:keys [id kind query] guards :when} fact-store scope explain? ctx]
   (let [matches     (query-matches query guards fact-store scope)
         all-matches (when explain? (doall matches))
         first-match (first (or all-matches matches))
         entry       (cond-> {:kind kind :query query}
                       id (assoc :id id))]
     (if first-match
       {:matched? true
        :kind     kind
        :explain  (cond-> (assoc entry :result :matched)
                    explain? (match-evidence first-match all-matches fact-store ctx))}
       {:matched? false
        :kind     kind
        :explain  (assoc entry :result :no-match)}))))

(defn- run-policies
  "Evaluates policies in order up to and including the first match.
   Returns the evaluated entries, each with its `:index`."
  [policies fact-store scope explain? ctx]
  (loop [i 0, ps (seq policies), acc []]
    (if-let [p (first ps)]
      (let [r   (eval-policy p fact-store scope explain? ctx)
            acc (conj acc (assoc (:explain r) :index i))]
        (if (:matched? r)
          acc
          (recur (inc i) (next ps) acc)))
      acc)))

(defn- decide
  "The authorization decision from check results and evaluated policy
   entries: `{:result :allow|:deny :reason … :decider entry}`.

   The result is binary and closed-world: only a matching `:allow` policy
   allows. When no policy applies — none matches (XACML's NotApplicable),
   or there are none at all — the result is deny, and `:reason` says which.
   The engine never hands the caller a third outcome to interpret.

   Reasons: `:check-failed`, `:policy` (the first matching policy's kind),
   `:no-matching-policy` (deny), `:no-policies` (deny: nothing can allow).
   Callers that treat a missing policy set as an error can check for
   `:no-policies` (also in `eval-token`'s `:warnings`) and throw."
  [check-results policies evaluated]
  (let [decider (some #(when (= :matched (:result %)) %) evaluated)]
    (cond
      (some #(= :fail (:result %)) check-results) {:result :deny :reason :check-failed}
      (empty? policies)                           {:result :deny :reason :no-policies}
      decider                                     {:result  (:kind decider)
                                                   :reason  :policy
                                                   :decider decider}
      :else                                       {:result :deny :reason :no-matching-policy})))

(defn eval-policies
  "Evaluates authorizer policies in order. First matching policy wins.

   - `:allow` match → `{:result :allow}`
   - `:deny` match → `{:result :deny}`
   - No match → `{:result :deny}` (closed-world default)
   - No policies → `{:result :deny}` (nothing can allow)

   Policies are only evaluated after all block checks pass."
  [policies fact-store scope]
  {:result (:result (decide [] policies (run-policies policies fact-store scope false nil)))})

(defn eval-checks
  "Evaluates all checks on the fact store with optional scope filtering.
   When explain? is true, all matches are realized for audit visibility."
  ([checks store]
   (map (fn [c] (eval-check c store nil false)) checks))
  ([checks store scope]
   (map (fn [c] (eval-check c store scope false)) checks))
  ([checks store scope explain?]
   (eval-checks checks store scope explain? nil))
  ([checks store scope explain? ctx]
   (map (fn [c] (eval-check c store scope explain? ctx)) checks)))

(defn- eval-token*
  "Evaluates a token whose patterns already passed the arity check. See `eval-token`."
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
        stated store

        {:keys [store derivations truncated? error]}
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
        explain? (assoc :explain {:type   :decision
                                  :result :deny
                                  :reason :limit-exceeded
                                  :error  error}))
      (let [;; Explain context for checks: what the fixpoint recorded
            ctx (when explain?
                  {:mode        (if (= :all explain?) :all :first)
                   :derivations derivations
                   :stated      stated
                   :truncated?  truncated?})

            tag-block (fn [results block]
                        (cond->> results
                          explain? (map #(assoc-in % [:explain :block] block))))

            ;; 5. Evaluate checks per block with scoped visibility
            block-results
            (mapcat
             (fn [idx]
               (let [block (nth blocks idx)
                     scope (trusted-origins idx)]
                 (tag-block (eval-checks (:checks block) store scope explain? ctx)
                            idx)))
             (range (count blocks)))

            ;; 6. Evaluate authorizer checks (with extended scope if trusted blocks)
            auth-scope (or authorizer-scope (trusted-origins nil))

            authorizer-results
            (when (:checks authorizer)
              (tag-block (eval-checks (:checks authorizer) store auth-scope explain? ctx)
                         :authorizer))

            all-results (cond-> (concat block-results authorizer-results)
                          explain? vec)
            failed? (some #(= :fail (:result %)) all-results)

            ;; 7. Evaluate authorizer policies (after all checks pass)
            policies  (:policies authorizer)
            evaluated (when-not failed?
                        (run-policies policies store auth-scope explain? ctx))
            {:keys [result reason decider]}
            (decide (when failed? [{:result :fail}]) policies evaluated)]
        (cond-> {:valid? (= :allow result)}
          explain?
          (assoc :explain
                 (let [checks   (mapv #(dissoc (:explain %) :facts :truncated?) all-results)
                       policies (mapv #(dissoc % :facts :truncated?) evaluated)
                       roots    (concat (mapcat :because checks) (:because decider))]
                   (cond-> {:type     :decision
                            :result   result
                            :reason   reason
                            :checks   checks
                            :policies policies
                            :facts    (explain-facts roots store
                                                     (:derivations ctx) (:stated ctx))}
                     truncated? (assoc :truncated? true)))))))))

(defn arity-mismatches
  "Predicates used with more than one length across `blocks` and the
   `authorizer` — facts, rule heads, rule bodies, checks and policies. A
   pattern only matches facts of its own length, so a mismatch is almost
   always a typo (a reject check or deny policy that can never fire).

   Returns a vector, sorted by predicate, of
   `{:predicate p :arities {length [location …]}}` where a location is
   `{:block idx|:authorizer :in :facts|:rule-head|:rule-body|:check|:policy}`
   plus the rule's, check's or policy's `:id` (or a policy's `:index`).
   Patterns whose first element is a variable are skipped. Empty when
   consistent."
  [blocks authorizer]
  (let [uses
        (for [[block src] (concat (map-indexed vector blocks)
                                  (when authorizer [[:authorizer authorizer]]))
              [in id-of patterns]
              (concat
               [[:facts nil (:facts src)]]
               (mapcat (fn [{:keys [id head body]}]
                         [[:rule-head id [head]] [:rule-body id body]])
                       (:rules src))
               (map (fn [{:keys [id query]}] [:check id query]) (:checks src))
               (map-indexed (fn [i {:keys [id query]}]
                              [:policy (if id [:id id] [:index i]) query])
                            (:policies src)))
              pattern patterns
              :when (and (sequential? pattern) (seq pattern)
                         (not (variable? (first pattern))))]
          [(first pattern) (count pattern)
           (cond-> {:block block :in in}
             (and id-of (not= in :policy)) (assoc :id id-of)
             (= in :policy) (assoc (first id-of) (second id-of)))])
        add-loc (fn [locs loc] (if (some #{loc} locs) locs (conj (or locs []) loc)))
        by-pred (reduce (fn [m [p n loc]] (update-in m [p n] add-loc loc))
                        {} uses)]
    (->> by-pred
         (filter (fn [[_ arities]] (> (count arities) 1)))
         (sort-by (comp str key))
         (mapv (fn [[p arities]]
                 {:predicate p :arities (into (sorted-map) arities)})))))

(defn check-keys
  "Throws `:stroopwafel/error :unknown-keys` when map `m` (named `what` in
   the message) has keys outside `allowed`: a misspelled option or
   authorizer key would otherwise be silently ignored — `:authoriser`
   dropped every deny policy."
  [what m allowed]
  (let [unknown (vec (remove allowed (keys m)))]
    (when (seq unknown)
      (throw (ex-info (str "Unknown " what ": " (pr-str unknown)
                           "; expected some of " (pr-str (sort allowed)))
                      {:stroopwafel/error :unknown-keys
                       :in                what
                       :unknown           unknown
                       :allowed           allowed})))))

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

   Accepts an `:authorizer` map with:
     - `:policies` — ordered allow/deny policies. With none (or no
       authorizer) nothing can allow: the result is deny, with `:reason
       :no-policies` and a `{:type :no-policies}` warning
     - `:facts`  — additional authorizer facts
     - `:checks` — additional authorizer checks
     - `:rules`  — additional authorizer rules

   Unknown options or authorizer keys throw (see `check-keys`).

   Accepts optional `:limits` (`:max-iterations`, `:max-facts`,
   `:max-derivations`) over `default-limits`. Reaching `:max-iterations` or
   `:max-facts` before the fixpoint denies; `:max-derivations` only
   truncates explain data.

   `:explain?` is `true` (one derivation per fact, the first found) or
   `:all` (every derivation, circular ones included). Both produce the same
   flat shape: see `eval-check`.

   Returns:
   |||
   |:-|:-|
   | `:valid?`  | boolean authorization decision
   | `:explain` | with :explain?, the decision map (below)

   The decision map is `{:type :decision :result :allow|:deny :reason …
   :checks [...] :policies [...] :facts {...}}`: every check with its
   `:block`, every evaluated policy (up to the deciding one) with its
   `:index`, and one fact table for all of them. `:reason` is
   `:check-failed`, `:policy`, `:no-matching-policy`, `:no-policies`
   or `:limit-exceeded` (then with `:error` instead of checks).
   | `:error`   | when a limit was reached: `{:type :limit-exceeded :limit :max :facts :iterations}`,
   |            | or with `:arity-check :error`: `{:type :arity-mismatch :mismatches [...]}`
   | `:warnings`| `{:type :arity-mismatch …}` with `:arity-check :warn` (the default), when
   |            | patterns disagree on length; `{:type :no-policies}` when there are no policies

   `:arity-check` (`:warn` default, `:error`, `:off`) checks that every use of a
   predicate — facts, rule heads and bodies, checks, policies — has the same
   length (see `arity-mismatches`). A mismatched pattern never matches, so a
   reject check or deny policy with a typo silently never fires. `:warn` adds
   `:warnings` and leaves the decision alone; `:error` denies before evaluating."
  [token & {:keys [explain? authorizer arity-check]
            :or   {arity-check :warn}
            :as   opts}]
  (check-keys "eval-token options" opts
              #{:explain? :authorizer :trusted-block-indices :limits :arity-check})
  (check-keys "authorizer keys" authorizer #{:facts :rules :checks :policies})
  (when-not (#{:warn :error :off} arity-check)
    (throw (ex-info "Invalid :arity-check: must be :warn, :error or :off"
                    {:arity-check arity-check})))
  (let [mismatches  (when-not (= :off arity-check)
                      (arity-mismatches (:blocks token) authorizer))
        no-policies (when (empty? (:policies authorizer))
                      [{:type :no-policies}])
        with-warnings (fn [result warnings]
                        (cond-> result
                          (seq warnings) (assoc :warnings (vec warnings))))]
    (if (and (seq mismatches) (= :error arity-check))
      (let [error {:type :arity-mismatch :mismatches mismatches}]
        (with-warnings
          (cond-> {:valid? false :error error}
            explain? (assoc :explain {:type   :decision
                                      :result :deny
                                      :reason :arity-mismatch
                                      :error  error}))
          no-policies))
      (with-warnings
        (apply eval-token* token (mapcat identity (dissoc opts :arity-check)))
        (concat (map #(assoc % :type :arity-mismatch) mismatches) no-policies)))))
