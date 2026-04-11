(ns stroopwafel.request
  "Signed requests for requester-bound tokens (proof-of-possession).

   A bearer token can be used by anyone who holds it. A requester-bound
   token binds authorization to a specific key — the presenter must prove
   they hold the corresponding private key by signing each request.

   Flow:
     1. Authority issues token with `[:authorized-agent-key agent-pk-bytes]`
     2. Agent signs each request with `sign-request`
     3. Execution service verifies with `verify-request`
     4. Verified agent-pk is added as authorizer fact
     5. Datalog join: `[:authorized-agent-key ?k]` ∧ `[:request-verified-agent-key ?k]`

   This is the SPKI model (subject-key binding) expressed as Datalog facts."
  (:require [stroopwafel.crypto :as crypto]))

(defn sign-request
  "Signs a request body with the agent's private key.

   The request body is canonicalized via CEDN, hashed with SHA-256,
   and signed with Ed25519. The result includes the original body,
   signature, agent's encoded public key, and a timestamp.

   Arguments:
     - `body`     : any CEDN-serializable value (the request payload)
     - `agent-sk` : agent's Ed25519 private key
     - `agent-pk` : agent's Ed25519 public key

   Returns:
     ```clojure
     {:body      <original body>
      :agent-key <X.509 encoded public key bytes>
      :sig       <Ed25519 signature bytes>
      :timestamp <milliseconds since epoch>}
     ```"
  [body agent-sk agent-pk]
  (let [ts        (System/currentTimeMillis)
        payload   {:body body :timestamp ts}
        sig-bytes (-> payload crypto/encode-block crypto/sha256
                      (->> (crypto/sign agent-sk)))]
    {:body      body
     :agent-key (crypto/encode-public-key agent-pk)
     :sig       sig-bytes
     :timestamp ts}))

(defn verify-request
  "Verifies a signed request's signature.

   Decodes the agent's public key from the request, reconstructs the
   signed payload, and verifies the Ed25519 signature.

   Arguments:
     - `signed-request` : map from `sign-request`

   Returns:
     The agent's encoded public key bytes if valid, nil if invalid."
  [signed-request]
  (let [{:keys [body agent-key sig timestamp]} signed-request
        payload  {:body body :timestamp timestamp}
        pub      (crypto/decode-public-key agent-key)
        hash     (crypto/sha256 (crypto/encode-block payload))]
    (when (crypto/verify pub hash sig)
      agent-key)))
