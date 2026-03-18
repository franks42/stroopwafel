(ns stroopwafel.authorize
  "Multi-token authorization context with PDP/PEP separation.

   Separates the authorization pipeline into discrete steps:
     1. Verify signed assertions (tokens, requests) — crypto
     2. Collect verified facts into a context
     3. Decide (PDP) — evaluate Datalog rules and policies
     4. Enforce (PEP) — application acts on the decision

   Usage:
     (-> (context)
         (add-token name-cert {:public-key idp-pk})
         (add-token capability {:public-key service-pk})
         (add-signed-request signed-req)
         (add-facts [[:time (System/currentTimeMillis)]])
         (authorize
           :rules    '[...]
           :policies '[...]))"
  (:require [stroopwafel.core :as core]
            [stroopwafel.crypto :as crypto]
            [stroopwafel.request :as request]))

(defn context
  "Creates an empty authorization context.

   The context accumulates verified facts, checks, rules, and
   third-party signer information from multiple tokens."
  []
  {:facts   []
   :checks  []
   :rules   []
   :signers []
   :errors  []})

(defn- extract-token-info
  "Extracts facts, checks, rules, and signer info from a verified token.

   Each block's facts are collected. Checks and rules are preserved
   for enforcement during authorization. Third-party block signers
   are tracked for delegation chain support."
  [token {:keys [trusted-external-keys]}]
  (let [blocks (:blocks token)
        trusted-encoded (when trusted-external-keys
                          (mapv crypto/encode-public-key trusted-external-keys))

        ;; Collect facts from all blocks
        ;; Authority block (0) facts are always included
        ;; Third-party block facts only if their signer is trusted
        block-info
        (map-indexed
         (fn [idx block]
           (let [ext-key    (:external-key block)
                 is-tp?     (some? ext-key)
                 trusted?   (and is-tp? trusted-encoded
                                 (some #(crypto/bytes= ext-key %) trusted-encoded))]
             {:idx        idx
              :facts      (:facts block)
              :checks     (or (:checks block) [])
              :rules      (or (:rules block) [])
              :external-key ext-key
              :third-party? is-tp?
              :trusted?   (or (not is-tp?) trusted?)}))
         blocks)

        ;; Facts from authority block + trusted blocks
        all-facts (into [] (mapcat :facts) (filter :trusted? block-info))

        ;; Checks from all blocks (even untrusted — checks restrict, never expand)
        all-checks (into [] (mapcat :checks) block-info)

        ;; Rules from authority block + trusted blocks
        all-rules (into [] (mapcat :rules) (filter :trusted? block-info))

        ;; Signer attribution for trusted third-party blocks
        signers (into []
                      (comp (filter :third-party?)
                            (filter :trusted?)
                            (map (fn [{:keys [idx external-key]}]
                                   [:block-signed-by idx external-key])))
                      block-info)]

    {:facts   all-facts
     :checks  all-checks
     :rules   all-rules
     :signers signers}))

(defn add-token
  "Verifies a token and adds its facts to the context.

   The token's signature chain is verified against the given public key.
   If verification fails, the error is recorded and no facts are added.
   If verification passes, authority-block facts, checks, rules, and
   third-party signer attribution are added to the context.

   Arguments:
     - `ctx`   : authorization context
     - `token` : token map
     - `opts`  : map with:
         `:public-key` — root public key for this token (required)
         `:trusted-external-keys` — vector of trusted third-party keys (optional)

   Returns updated context."
  [ctx token opts]
  (if-not (core/verify token {:public-key (:public-key opts)})
    (update ctx :errors conj {:reason :invalid-token})
    (let [info (extract-token-info token opts)]
      (-> ctx
          (update :facts into (:facts info))
          (update :facts into (:signers info))
          (update :checks into (:checks info))
          (update :rules into (:rules info))))))

(defn add-signed-request
  "Verifies a signed request and adds the agent key to the context.

   If verification fails, the error is recorded.
   If verification passes, `[:request-verified-agent-key key-bytes]`
   is added as a fact.

   Arguments:
     - `ctx`            : authorization context
     - `signed-request` : map from `stroopwafel.request/sign-request`

   Returns updated context."
  [ctx signed-request]
  (if-let [agent-key (request/verify-request signed-request)]
    (update ctx :facts conj [:request-verified-agent-key agent-key])
    (update ctx :errors conj {:reason :invalid-request-signature})))

(defn add-facts
  "Adds runtime facts (e.g., current time, request metadata) to the context.

   These facts are not cryptographically signed — they represent
   the execution service's own assertions about the current request.

   Arguments:
     - `ctx`   : authorization context
     - `facts` : vector of fact tuples

   Returns updated context."
  [ctx facts]
  (update ctx :facts into facts))

(defn authorize
  "Makes a policy decision based on the accumulated context (PDP).

   All verified facts, checks, and rules from added tokens are combined.
   The provided rules and policies are added to the evaluation.
   All checks must pass, then the first matching policy determines
   the result.

   If any token or request failed verification, authorization is
   denied immediately.

   Arguments:
     - `ctx` : authorization context
     - keyword args:
         `:rules`    — additional authorizer rules
         `:checks`   — additional authorizer checks
         `:policies` — ordered allow/deny policies (first match wins)
         `:explain?` — include proof tree in result

   Returns:
     `{:allowed? boolean}` or `{:allowed? false :errors [...]}`"
  [ctx & {:keys [rules checks policies explain?]}]
  (if (seq (:errors ctx))
    {:allowed? false :errors (:errors ctx)}
    (let [;; Build a synthetic single-block token from all collected facts
          ;; Token checks enforce restrictions from each contributing token
          synthetic-token
          {:blocks [{:facts  (:facts ctx)
                     :rules  (:rules ctx)
                     :checks (:checks ctx)}]}

          ;; Authorizer provides the policy decision rules
          authorizer {:rules    (or rules [])
                      :checks   (or checks [])
                      :policies (or policies [])}

          result (core/evaluate synthetic-token
                   :explain? explain?
                   :authorizer authorizer)]
      (cond-> {:allowed? (:valid? result)}
        explain? (assoc :explain (:explain result))))))
