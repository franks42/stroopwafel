(ns stroopwafel.core
  "Pure Assertions-DL engine — Datalog evaluation over facts and rules.

   No crypto, no signing, no keys, no envelopes. Just facts in, decision out.

   Blocks are plain maps with :facts, :rules, :checks. The caller is
   responsible for signature verification and fact extraction before
   calling evaluate. This separation means the engine has zero external
   dependencies and can be embedded anywhere."
  (:require [stroopwafel.datalog :as datalog]
            [stroopwafel.graph :as graph]))

(defn evaluate
  "Evaluates a token (collection of fact blocks) against Datalog policy.

   This is the single entry point for authorization decisions. The token
   must already be cryptographically verified — this function performs
   only logical evaluation.

   Arguments:
     - `token` : map with `:blocks` — a vector of block maps, each containing:
         `:facts`  — vector of fact tuples
         `:rules`  — vector of rule maps (optional)
         `:checks` — vector of check maps (optional)
         `:external-key` — (optional) byte array identifying third-party signer
     - keyword args:
         `:explain?`   (true or :all) — include the decision explain in result
         `:authorizer` (map)     — authorizer context with:
           `:policies` — ordered allow/deny policies (first match wins).
             Only a matching `:allow` allows: with no policies (or no
             authorizer) the result is deny, with a `{:type :no-policies}`
             warning. To allow whatever passes the checks, use
             `{:kind :allow :query []}`
           `:facts`    — additional authorizer facts
           `:checks`   — additional authorizer checks
           `:rules`    — additional authorizer rules
           `:trusted-external-keys` — vector of trusted third-party key bytes
         `:limits`     (map)     — fixpoint limits over `datalog/default-limits`:
           `:max-iterations` (100) and `:max-facts` (1000). Reaching a
           limit before the fixpoint denies (fail closed); unknown keys or
           non-positive values throw. `:max-derivations` (10000) only caps
           explain data
         `:arity-check` — `:warn` (default), `:error` or `:off`: whether
           predicates used with different lengths add `:warnings`, deny,
           or are ignored (see `check-arity`)

   Returns:
     ```clojure
     {:valid?  boolean
      :explain decision map (when :explain?)
      :error   {:type :limit-exceeded …} or {:type :arity-mismatch …}
               (only when a limit was reached, or with :arity-check :error)
      :warnings [{:type :arity-mismatch …} (only with :arity-check :warn)
                 {:type :no-policies}]}         (when there are no policies)
     ```

   The decision is binary and closed-world: whenever no policy allows —
   none matches, none exists, a check failed, a limit was reached — it is
   deny, and `:reason` (in the explain) and `:warnings` say why. The
   caller never gets a third outcome to interpret; one that treats a
   missing policy set as an error can check the warnings and throw.

   Throws only on a malformed call (ex-data `:stroopwafel/error`):
   `:unknown-keys` (a misspelled option or authorizer key, which would
   otherwise be silently ignored), and invalid `:limits` or `:arity-check`.

   Block scope isolation:
     - Block 0 checks see: #{0 :authorizer}
     - Block N checks see: #{0 N :authorizer}
     - Authorizer policies see: #{0 :authorizer} (+ trusted third-party indices)"
  [token & {:keys [explain? authorizer limits arity-check]
            :or   {arity-check :warn}
            :as   opts}]
  (datalog/check-keys "evaluate options" opts
                      #{:explain? :authorizer :limits :arity-check})
  (datalog/check-keys "authorizer keys" authorizer
                      #{:facts :rules :checks :policies :trusted-external-keys})
  (let [blocks (:blocks token)

        ;; Extract logical content from each block
        core-token
        {:blocks
         (mapv (fn [block]
                 (select-keys block [:facts :rules :checks]))
               blocks)}

        ;; Compute trusted third-party block indices and signer attribution
        trusted-keys (:trusted-external-keys authorizer)

        trusted-info
        (when (seq trusted-keys)
          (keep-indexed
           (fn [idx block]
             (when-let [ext-key (:external-key block)]
               (when (some #(datalog/value= ext-key %) trusted-keys)
                 {:idx idx :external-key ext-key})))
           blocks))

        trusted-block-indices (when (seq trusted-info)
                                (into #{} (map :idx) trusted-info))

        ;; Auto-inject [:block-signed-by <block-idx> <external-key-bytes>]
        ;; for each trusted third-party block — enables Datalog delegation chains
        signer-facts (mapv (fn [{:keys [idx external-key]}]
                             [:block-signed-by idx external-key])
                           trusted-info)

        authorizer-with-signers
        (update (dissoc authorizer :trusted-external-keys)
                :facts into signer-facts)]

    (datalog/eval-token core-token
                        :explain? explain?
                        :authorizer authorizer-with-signers
                        :trusted-block-indices trusted-block-indices
                        :limits limits
                        :arity-check arity-check)))

(defn check-arity
  "Finds predicates used with more than one length in `token` and the
   `:authorizer` — facts, rule heads and bodies, checks and policies.
   A pattern only matches facts of its own length, so a mismatch is
   almost always a typo; in a reject check or deny policy it silently
   never fires.

   Run it on a policy set before storing it (`{:blocks []}` plus the
   authorizer), so a typo is caught before it reaches evaluation.

   Returns `[]` when consistent, otherwise a vector of
   `{:predicate p :arities {length [location …]}}` — see
   `datalog/arity-mismatches`."
  [token & {:keys [authorizer]}]
  (datalog/arity-mismatches
   (mapv #(select-keys % [:facts :rules :checks]) (:blocks token))
   (dissoc authorizer :trusted-external-keys)))

(defn graph
  "Converts an explain tree into a graph representation.

   Arguments:
     - `explain-tree` (returned from evaluate with :explain? true)

   Returns:
    ```clojure
     {:root  node-id
      :nodes {node-id -> node}
      :edges [{:from id :to id :label kw} ...]}
    ```

   Pure data transformation — no authorization logic."
  [explain-tree]
  (graph/explain->graph explain-tree))
