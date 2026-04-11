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
         `:explain?`   (boolean) — include proof tree in result
         `:authorizer` (map)     — authorizer context with:
           `:facts`    — additional authorizer facts
           `:checks`   — additional authorizer checks
           `:rules`    — additional authorizer rules
           `:policies` — ordered allow/deny policies (first match wins)
           `:trusted-external-keys` — vector of trusted third-party key bytes

   Returns:
     ```clojure
     {:valid?  boolean
      :explain explain-tree (when :explain? true)}
     ```

   Block scope isolation:
     - Block 0 checks see: #{0 :authorizer}
     - Block N checks see: #{0 N :authorizer}
     - Authorizer policies see: #{0 :authorizer} (+ trusted third-party indices)"
  [token & {:keys [explain? authorizer]}]
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
                        :trusted-block-indices trusted-block-indices)))

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
