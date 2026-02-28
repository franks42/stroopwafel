(ns stroopwafel.block
  (:require [stroopwafel.crypto :as c]))

(defn authority-block
  "Creates and signs the initial (authority) block of a token chain.

   Generates a fresh ephemeral keypair. The ephemeral public key is
   embedded in the block payload (`:next-key`), and the ephemeral
   private key is returned alongside the block for future attenuation.

   The block is signed with the root private key.

   Arguments:
     - `facts`       : vector of fact tuples
     - `rules`       : vector of rule maps
     - `checks`      : vector of check maps
     - `private-key` : root java.security.PrivateKey

   Returns:
     `{:block <block-map> :next-private-key <PrivateKey>}`"
  [facts rules checks privkey]
  (let [eph-kp  (c/generate-keypair "Ed25519")
        eph-pub (c/encode-public-key (.getPublic eph-kp))
        payload {:facts    facts
                 :rules    rules
                 :checks   checks
                 :prev-sig nil
                 :next-key eph-pub}
        bytes   (c/encode-block payload)
        hash    (c/sha256 bytes)
        sig     (c/sign privkey hash)]
    {:block            (assoc payload :hash hash :sig sig)
     :next-private-key (.getPrivate eph-kp)}))

(defn delegated-block
  "Creates and signs a new block that extends an existing block chain.

   Signs with the current ephemeral private key and generates a fresh
   ephemeral keypair for the next block. The previous block's signature
   is included in the payload (`:prev-sig`), binding blocks into an
   unbreakable cryptographic chain.

   Arguments:
     - `prev-block`  : the immediately preceding block in the chain
     - `facts`       : additional fact tuples
     - `rules`       : additional rule maps
     - `checks`      : additional check maps
     - `eph-privkey` : current ephemeral java.security.PrivateKey

   Returns:
     `{:block <block-map> :next-private-key <PrivateKey>}`"
  [prev-block facts rules checks eph-privkey]
  (let [eph-kp  (c/generate-keypair "Ed25519")
        eph-pub (c/encode-public-key (.getPublic eph-kp))
        payload {:facts    facts
                 :rules    rules
                 :checks   checks
                 :prev-sig (:sig prev-block)
                 :next-key eph-pub}
        bytes   (c/encode-block payload)
        hash    (c/sha256 bytes)
        sig     (c/sign eph-privkey hash)]
    {:block            (assoc payload :hash hash :sig sig)
     :next-private-key (.getPrivate eph-kp)}))

(defn verify-chain
  "Verifies the integrity and authenticity of a sequence of blocks.

   Validates the ephemeral key chain: block 0 is verified with the root
   public key, each subsequent block is verified with the previous
   block's `:next-key`. Also verifies that each block's `:prev-sig`
   matches the previous block's `:sig`.

   Arguments:
     - `blocks`     : vector of block maps (authority -> latest)
     - `public-key` : root java.security.PublicKey

   Returns:
     - `true`  if the entire chain is valid
     - `false` otherwise"
  [blocks pubkey]
  (loop [[b & more] blocks
         verify-key pubkey
         prev-sig   nil]
    (if (nil? b)
      true
      (let [{:keys [sig next-key]} b
            payload  (dissoc b :hash :sig)
            bytes    (c/encode-block payload)
            hash     (c/sha256 bytes)
            hash-ok? (c/bytes= (:hash b) hash)
            sig-ok?  (c/verify verify-key hash sig)
            prev-ok? (if prev-sig
                       (c/bytes= (:prev-sig b) prev-sig)
                       (nil? (:prev-sig b)))]
        (and hash-ok?
             sig-ok?
             prev-ok?
             (recur more
                    (c/decode-public-key next-key)
                    sig))))))
