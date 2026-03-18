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

(defn sealed?
  "Returns true if the token is sealed (cannot be further attenuated)."
  [token]
  (map? (:proof token)))

(defn attenuate
  "Appends a new delegated block to an existing token.

   Uses the token's proof (ephemeral private key) to sign the new
   block. Generates a fresh ephemeral keypair — the new token's
   proof enables further attenuation.

   No explicit key argument needed — whoever holds the token can
   attenuate it. This is the core capability model.

   Throws if the token is sealed.

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
  (when (sealed? token)
    (throw (ex-info "Cannot attenuate a sealed token" {})))
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

(defn third-party-request
  "Extracts a third-party block request from a token.

   The request contains the previous signature needed by the third party
   to bind their signed block to this specific token instance.

   Throws if the token is sealed.

   Arguments:
     - `token` : unsealed token map

   Returns:
     `{:previous-sig <bytes>}`"
  [token]
  (when (sealed? token)
    (throw (ex-info "Cannot create third-party request from a sealed token" {})))
  {:previous-sig (:sig (peek (:blocks token)))})

(defn create-third-party-block
  "Creates a third-party signed block (called by the external party).

   The third party signs `SHA-256(encode-block({:facts :rules :checks :previous-sig}))`
   binding the block content to a specific token instance via `previous-sig`.

   Arguments:
     - `request` : map with `:previous-sig` (from `third-party-request`)
     - `payload` : map with `:facts`, `:rules`, `:checks`
     - `opts`    : map with `:private-key` and `:public-key` (third party's keys)

   Returns:
     `{:facts [...] :rules [...] :checks [...] :external-sig <bytes> :external-key <bytes>}`"
  [request payload {:keys [private-key public-key]}]
  (let [facts  (or (:facts payload) [])
        rules  (or (:rules payload) [])
        checks (or (:checks payload) [])
        ext-payload {:facts        facts
                     :rules        rules
                     :checks       checks
                     :previous-sig (:previous-sig request)}
        ext-bytes   (crypto/encode-block ext-payload)
        ext-hash    (crypto/sha256 ext-bytes)
        ext-sig     (crypto/sign private-key ext-hash)]
    {:facts        facts
     :rules        rules
     :checks       checks
     :external-sig ext-sig
     :external-key (crypto/encode-public-key public-key)}))

(defn append-third-party
  "Appends a third-party signed block to a token.

   The token holder calls this after receiving the signed block from
   the third party. Delegates to `block/third-party-block` to maintain
   the ephemeral key chain.

   Throws if the token is sealed.

   Arguments:
     - `token`    : unsealed token map
     - `tp-block` : third-party block map from `create-third-party-block`

   Returns:
     A new token map with the third-party block appended."
  [token tp-block]
  (when (sealed? token)
    (throw (ex-info "Cannot append to a sealed token" {})))
  (let [prev-block (peek (:blocks token))
        {:keys [block next-private-key]}
        (block/third-party-block prev-block tp-block (:proof token))]
    {:blocks (conj (:blocks token) block)
     :proof  next-private-key}))

(defn seal
  "Seals a token to prevent further attenuation.

   Signs the last block's hash with the current ephemeral private key,
   then discards the key. The proof becomes a signature that can be
   verified against the last block's `:next-key`, but no one can
   append new blocks.

   Arguments:
     - `token` : unsealed token map

   Returns:
     A sealed token map. Calling `attenuate` on a sealed token
     will throw."
  [token]
  (when (sealed? token)
    (throw (ex-info "Token is already sealed" {})))
  (let [last-block (peek (:blocks token))
        seal-sig   (crypto/sign (:proof token) (:hash last-block))]
    {:blocks (:blocks token)
     :proof  {:type :sealed :sig seal-sig}}))

(defn verify
  "Verifies the integrity and authenticity of a token.

   Validates the ephemeral key chain: the authority block is verified
   with the root public key, each subsequent block is verified with
   the previous block's ephemeral public key.

   For sealed tokens, also verifies the seal signature against the
   last block's ephemeral public key.

   Arguments:
     - `token` : token map with `:blocks` and `:proof`
     - `opts`  : map with `:public-key` (root public key)

   Returns:
     - `true` if the block chain (and seal, if present) is valid
     - `false` otherwise"
  [token {:keys [public-key] :as _opts}]
  (let [chain-ok? (block/verify-chain (:blocks token) public-key)]
    (if (and chain-ok? (sealed? token))
      (let [last-block (peek (:blocks token))
            seal-key   (crypto/decode-public-key (:next-key last-block))]
        (crypto/verify seal-key
                       (:hash last-block)
                       (get-in token [:proof :sig])))
      chain-ok?)))

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
               (:blocks token))}

        ;; Compute trusted third-party block indices and signer attribution
        trusted-keys (:trusted-external-keys authorizer)
        trusted-encoded (when trusted-keys
                          (mapv crypto/encode-public-key trusted-keys))
        trusted-info
        (when trusted-encoded
          (keep-indexed
           (fn [idx block]
             (when-let [ext-key (:external-key block)]
               (when (some #(crypto/bytes= ext-key %) trusted-encoded)
                 {:idx idx :external-key ext-key})))
           (:blocks token)))

        trusted-block-indices (when trusted-info
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
