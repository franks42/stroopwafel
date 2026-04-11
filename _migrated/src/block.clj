(ns stroopwafel.block
  "Block chain construction and verification using signed envelopes.

   Every block is a signed envelope wrapping a message containing
   facts, rules, checks, and chain linkage. One signing format,
   one verification path — no special-casing."
  (:require [stroopwafel.crypto :as c]
            [stroopwafel.envelope :as envelope]))

(defn- block-message
  "Construct the block message content (the signed payload)."
  [facts rules checks prev-sig next-key-bytes & [{:keys [external-sig external-key]}]]
  (cond-> {:facts    facts
           :rules    rules
           :checks   checks
           :prev-sig prev-sig
           :next-key next-key-bytes}
    external-sig (assoc :external-sig external-sig)
    external-key (assoc :external-key external-key)))

(defn authority-block
  "Creates and signs the initial (authority) block of a token chain.

   Generates a fresh ephemeral keypair. The ephemeral public key is
   embedded in the block message (:next-key), and the ephemeral
   private key is returned alongside the signed envelope.

   The block is signed with the root private key. The signer-key in the
   envelope identifies the root authority. The request-id provides a
   timestamp for when the block was signed.

   Arguments:
     - `facts`       : vector of fact tuples
     - `rules`       : vector of rule maps
     - `checks`      : vector of check maps
     - `private-key` : root java.security.PrivateKey
     - `public-key`  : root java.security.PublicKey

   Returns:
     `{:block <signed-envelope> :next-private-key <PrivateKey>}`"
  [facts rules checks private-key public-key]
  (let [eph-kp  (c/generate-keypair "Ed25519")
        eph-pub (c/encode-public-key (.getPublic eph-kp))
        message (block-message facts rules checks nil eph-pub)
        signed  (envelope/sign message private-key public-key)]
    {:block            signed
     :next-private-key (.getPrivate eph-kp)}))

(defn delegated-block
  "Creates and signs a new block that extends an existing block chain.

   Signs with the current ephemeral private key and generates a fresh
   ephemeral keypair for the next block. The previous block's signature
   is included in the message (:prev-sig), binding blocks into an
   unbreakable cryptographic chain.

   Arguments:
     - `prev-block`  : the immediately preceding signed envelope
     - `facts`       : additional fact tuples
     - `rules`       : additional rule maps
     - `checks`      : additional check maps
     - `eph-privkey` : current ephemeral java.security.PrivateKey
     - `eph-pubkey`  : current ephemeral java.security.PublicKey

   Returns:
     `{:block <signed-envelope> :next-private-key <PrivateKey>}`"
  [prev-block facts rules checks eph-privkey eph-pubkey]
  (let [eph-kp  (c/generate-keypair "Ed25519")
        eph-pub (c/encode-public-key (.getPublic eph-kp))
        message (block-message facts rules checks (:signature prev-block) eph-pub)
        signed  (envelope/sign message eph-privkey eph-pubkey)]
    {:block            signed
     :next-private-key (.getPrivate eph-kp)}))

(defn third-party-block
  "Creates and signs a block that includes a third-party external signature.

   The token holder calls this to append a third-party-signed block to the
   chain. The block message includes :external-sig and :external-key
   from the third party's response.

   Arguments:
     - `prev-block`    : the immediately preceding signed envelope
     - `tp-block`      : third-party block map with :facts, :rules, :checks,
                          :external-sig, :external-key
     - `eph-privkey`   : current ephemeral java.security.PrivateKey
     - `eph-pubkey`    : current ephemeral java.security.PublicKey

   Returns:
     `{:block <signed-envelope> :next-private-key <PrivateKey>}`"
  [prev-block tp-block eph-privkey eph-pubkey]
  (let [eph-kp  (c/generate-keypair "Ed25519")
        eph-pub (c/encode-public-key (.getPublic eph-kp))
        message (block-message
                 (or (:facts tp-block) [])
                 (or (:rules tp-block) [])
                 (or (:checks tp-block) [])
                 (:signature prev-block)
                 eph-pub
                 {:external-sig (:external-sig tp-block)
                  :external-key (:external-key tp-block)})
        signed  (envelope/sign message eph-privkey eph-pubkey)]
    {:block            signed
     :next-private-key (.getPrivate eph-kp)}))

(defn verify-chain
  "Verifies the integrity and authenticity of a chain of signed-envelope blocks.

   Each block is verified via envelope/verify. Then the chain linkage is checked:
   block 0's signer-key must match the root public key, each subsequent block's
   signer-key must match the previous block's :next-key. Each block's :prev-sig
   must match the previous block's signature.

   For third-party blocks, verifies the external signature against the
   external key and the previous signature binding.

   Arguments:
     - `blocks`         : vector of signed envelopes
     - `root-pk-bytes`  : encoded root public key bytes

   Returns:
     - `true`  if the entire chain is valid
     - `false` otherwise"
  [blocks root-pk-bytes]
  (loop [[b & more] blocks
         expected-signer root-pk-bytes
         prev-sig nil]
    (if (nil? b)
      true
      (let [result  (envelope/verify b)
            message (:message result)
            signer  (:signer-key result)]
        (if-not (:valid? result)
          false
          (let [signer-ok? (c/bytes= signer expected-signer)
                prev-ok?   (if prev-sig
                             (c/bytes= (:prev-sig message) prev-sig)
                             (nil? (:prev-sig message)))
                ext-ok?    (if (:external-sig message)
                             (let [ext-payload {:facts       (:facts message)
                                                :rules       (:rules message)
                                                :checks      (:checks message)
                                                :previous-sig prev-sig}
                                   ext-bytes   (c/encode-block ext-payload)
                                   ext-hash    (c/sha256 ext-bytes)
                                   ext-pubkey  (c/decode-public-key (:external-key message))]
                               (c/verify ext-pubkey ext-hash (:external-sig message)))
                             true)]
            (and signer-ok?
                 prev-ok?
                 ext-ok?
                 (recur more
                        (:next-key message)
                        (:signature b)))))))))
