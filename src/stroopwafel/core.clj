(ns stroopwafel.core
  (:require [stroopwafel.block :as block]
            [stroopwafel.datalog :as datalog]
            [stroopwafel.graph :as graph]
            [stroopwafel.crypto :as crypto]))

(defn new-keypair
  "Helper to generate a new asymmetric keypair for signing and verification

   Returns a `java.security.KeyPair` instance containing:
     - a private key (used for signing blocks)
     - a public key  (used for verification)

   Uses Ed25519 algoritm in this PoC"
  []
  (let [kp (crypto/generate-keypair "Ed25519")]
    {:priv (.getPrivate kp)
     :pub (.getPublic kp)}))

(defn issue
  "Creates a new authority token.

   Generates a fresh ephemeral keypair for future attenuation. The
   ephemeral public key is embedded in the authority block; the
   ephemeral private key is stored in the token as `:proof`.

   Arguments:
     - payload map with:
       |||
       |:-|:-|
       | `:facts`  | vector of fact tuples
       | `:rules`  | vector of rule maps
       | `:checks` | vector of check maps (optional)
     - opts map with:
         `:private-key` — root private key (required)

   Returns:
     A token map:
     ```clojure
     {:blocks [authority-block]
      :proof  <ephemeral-private-key>}
     ```"
  [{:keys [facts rules checks] :as _blocks} {:keys [private-key] :as _opts}]
  (let [{:keys [block next-private-key]}
        (block/authority-block
         (or facts [])
         (or rules [])
         (or checks [])
         private-key)]
    {:blocks [block]
     :proof  next-private-key}))

(defn attenuate
  "Appends a new delegated block to an existing token.

   Uses the token's proof (ephemeral private key) to sign the new
   block. Generates a fresh ephemeral keypair — the new token's
   proof enables further attenuation.

   No explicit key argument needed — whoever holds the token can
   attenuate it. This is the core capability model.

   Arguments:
     - `token`   : token map with `:blocks` and `:proof`
     - payload : map with optional keys:
       |||
       |:-|:-|
       |`:facts`| vector of fact tuples
       |`:rules`| vector of rule maps
       |`:checks`| vector of check maps (optional)

   Returns:
     A new token map with the additional block appended."
  [token {:keys [facts rules checks] :as _blocks}]
  (let [prev-block (peek (:blocks token))
        {:keys [block next-private-key]}
        (block/delegated-block
         prev-block
         (or facts [])
         (or rules [])
         (or checks [])
         (:proof token))]
    {:blocks (conj (:blocks token) block)
     :proof  next-private-key}))

(defn verify
  "Verifies the integrity and authenticity of a token.

   Validates the ephemeral key chain: the authority block is verified
   with the root public key, each subsequent block is verified with
   the previous block's ephemeral public key.

   Arguments:
     - `token` : token map with `:blocks`
     - `opts`  : map with `:public-key` (root public key)

   Returns:
     - `true` if the block chain is valid
     - `false` otherwise"
  [token {:keys [public-key] :as _opts}]
  (block/verify-chain (:blocks token) public-key))

(defn evaluate
  "Evaluates an already verified token against its internal checks.

   Arguments:
     - `token` : token map with `:blocks`
     - keyword args:
         `:explain?`   (boolean) — include proof tree in result
         `:authorizer` (map)     — authorizer context with:
           `:facts`    — additional authorizer facts
           `:checks`   — additional authorizer checks
           `:rules`    — additional authorizer rules
           `:policies` — ordered allow/deny policies (first match wins)

   Returns:

    ```clojure
     {:valid?  boolean
      :explain explain-tree (when :explain? true)}
    ```
   It does:
     1. Extracts logical content (:facts, :rules, :checks)
     2. Delegates evaluation to the core engine with scope isolation
     3. Returns the authorization decision

   **IMPORTANT**:
     Assumes the token has already been
     cryptographically verified."
  [token & {:keys [explain? authorizer]}]
  (let [core-token
        {:blocks
         (mapv #(select-keys % [:facts :rules :checks])
               (:blocks token))}]
    (datalog/eval-token core-token
                        :explain? explain?
                        :authorizer authorizer)))

(defn revocation-ids
  "Extracts revocation IDs from a token.

   Each block's revocation ID is the SHA-256 hash of its signature,
   returned as a lowercase hex string. Applications can maintain
   revocation sets or bloom filters to invalidate tokens.

   Revoking any block's ID invalidates the entire token (since the
   chain is append-only, revoking an earlier block invalidates all
   subsequent blocks too).

   Arguments:
     - `token` : token map with `:blocks`

   Returns:
     A vector of hex strings, one per block, in chain order."
  [token]
  (mapv (fn [block]
          (let [sig-hash (crypto/sha256 (:sig block))]
            (apply str (map #(format "%02x" %) sig-hash))))
        (:blocks token)))

(defn graph
  "Converts an explain tree into a graph representation.

   Arguments:
     - `explain-tree` (returned from stroopwafel.core/evaluate)

   Returns:
    ```clojure
     {:root  node-id
      :nodes {node-id -> node}
      :edges [{:from id :to id :label kw} ...]}
    ```
   The resulting graph is suitable for:
     - visualization (Graphviz, etc.)
     - audit logging
     - debugging
     - API responses

   Performs no authorization logic.
   It is a pure transformation."
  [explain-tree]
  (graph/explain->graph explain-tree))
