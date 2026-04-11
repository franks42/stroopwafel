(ns stroopwafel.crypto-test
  (:require [stroopwafel.crypto :as sut]
            [stroopwafel.block :as block]
            [clojure.test :as t]))

(t/deftest canonical-map-order-test
  (t/testing "map key order does not affect canonical form"
    (t/is (= (sut/canonical {:b 2 :a 1})
             (sut/canonical {:a 1 :b 2})))))

(t/deftest canonical-nested-structure-test
  (t/testing "nested structures are canonicalized recursively"
    (t/is (= (sut/canonical {:z #{3 2 1}
                             :a [{:y 2 :x 1}]})
             (sut/canonical {:a [{:x 1 :y 2}]
                             :z #{1 2 3}})))))

(t/deftest canonical-vector-order-preserved
  (t/testing "vector order is preserved"
    (t/is (not=
           (sut/canonical [1 2 3])
           (sut/canonical [3 2 1])))))

(t/deftest sha256-deterministic-test
  (t/testing "same input yields same hash"
    (let [data (.getBytes "hello")]
      (t/is (sut/bytes=
             (sut/sha256 data)
             (sut/sha256 data))))))

(t/deftest sign-and-verify-test
  (t/testing "valid signature verifies"
    (let [kp   (sut/generate-keypair "Ed25519")
          msg  (.getBytes "important-data")
          sig  (sut/sign (.getPrivate kp) msg)]
      (t/is (true?
             (sut/verify
              (.getPublic kp)
              msg
              sig))))))

(t/deftest signature-fails-on-data-change
  (t/testing "signature fails if data changes"
    (let [kp   (sut/generate-keypair "Ed25519")
          msg  (.getBytes "important-data")
          sig  (sut/sign (.getPrivate kp) msg)]
      (t/is (false?
             (sut/verify
              (.getPublic kp)
              (.getBytes "tampered-data")
              sig))))))

(t/deftest signature-fails-with-wrong-key
  (t/testing "signature fails with wrong public key"
    (let [kp1  (sut/generate-keypair "Ed25519")
          kp2  (sut/generate-keypair "Ed25519")
          msg  (.getBytes "important-data")
          sig  (sut/sign (.getPrivate kp1) msg)]
      (t/is (false?
             (sut/verify
              (.getPublic kp2)
              msg
              sig))))))

(t/deftest encode-decode-public-key-roundtrip
  (t/testing "public key survives encode/decode round-trip"
    (let [kp      (sut/generate-keypair "Ed25519")
          pub     (.getPublic kp)
          encoded (sut/encode-public-key pub)
          decoded (sut/decode-public-key encoded)]
      (t/is (sut/bytes=
             (sut/encode-public-key pub)
             (sut/encode-public-key decoded))))))

(t/deftest authority-block-test
  (t/testing "authority block is self-contained and signed"
    (let [kp     (sut/generate-keypair "Ed25519")
          result (block/authority-block
                  [[:user "alice"]]
                  []
                  []
                  (.getPrivate kp)
                  (.getPublic kp))
          blk    (:block result)]
      (t/is (some? (:signature blk)))
      (t/is (nil? (get-in blk [:envelope :message :prev-sig])))
      (t/is (some? (get-in blk [:envelope :message :next-key])))
      (t/is (some? (:next-private-key result))))))

(t/deftest delegated-block-links-to-previous
  (t/testing "delegated block's prev-sig matches authority sig"
    (let [kp  (sut/generate-keypair "Ed25519")
          r0  (block/authority-block
               [[:user "alice"]]
               []
               []
               (.getPrivate kp)
               (.getPublic kp))
          b0  (:block r0)
          r1  (block/delegated-block
               b0 [] [] []
               (:next-private-key r0)
               (sut/decode-public-key (get-in b0 [:envelope :message :next-key])))
          b1  (:block r1)]
      (t/is (sut/bytes= (:signature b0) (get-in b1 [:envelope :message :prev-sig]))))))

(t/deftest verify-chain-valid
  (t/testing "valid ephemeral key chain verifies"
    (let [kp  (sut/generate-keypair "Ed25519")
          pub (.getPublic kp)
          r0  (block/authority-block
               [[:user "alice"]] [] []
               (.getPrivate kp)
               (.getPublic kp))
          r1  (block/delegated-block
               (:block r0) [] [] []
               (:next-private-key r0)
               (sut/decode-public-key (get-in (:block r0) [:envelope :message :next-key])))]
      (t/is (true?
             (block/verify-chain
              [(:block r0) (:block r1)] (sut/encode-public-key pub)))))))

(t/deftest verify-chain-fails-on-tampered-block
  (t/testing "tampered block breaks chain"
    (let [kp  (sut/generate-keypair "Ed25519")
          pub (.getPublic kp)
          r0  (block/authority-block
               [[:user "alice"]] [] []
               (.getPrivate kp)
               (.getPublic kp))
          r1  (block/delegated-block
               (:block r0) [] [] []
               (:next-private-key r0)
               (sut/decode-public-key (get-in (:block r0) [:envelope :message :next-key])))
          b1-tampered (assoc-in (:block r1) [:envelope :message :facts] [[:user "mallory"]])]
      (t/is (false?
             (block/verify-chain
              [(:block r0) b1-tampered] (sut/encode-public-key pub)))))))

(t/deftest verify-chain-fails-on-reordered-blocks
  (t/testing "reordering blocks breaks chain"
    (let [kp  (sut/generate-keypair "Ed25519")
          pub (.getPublic kp)
          r0  (block/authority-block
               [[:user "alice"]] [] []
               (.getPrivate kp)
               (.getPublic kp))
          r1  (block/delegated-block
               (:block r0) [] [] []
               (:next-private-key r0)
               (sut/decode-public-key (get-in (:block r0) [:envelope :message :next-key])))]
      (t/is (false?
             (block/verify-chain
              [(:block r1) (:block r0)] (sut/encode-public-key pub)))))))

(t/deftest ephemeral-keys-are-unique-per-block
  (t/testing "each block gets a distinct ephemeral public key"
    (let [kp  (sut/generate-keypair "Ed25519")
          r0  (block/authority-block
               [[:user "alice"]] [] []
               (.getPrivate kp)
               (.getPublic kp))
          r1  (block/delegated-block
               (:block r0) [] [] []
               (:next-private-key r0)
               (sut/decode-public-key (get-in (:block r0) [:envelope :message :next-key])))
          r2  (block/delegated-block
               (:block r1) [] [] []
               (:next-private-key r1)
               (sut/decode-public-key (get-in (:block r1) [:envelope :message :next-key])))]
      (t/is (not (sut/bytes=
                  (get-in (:block r0) [:envelope :message :next-key])
                  (get-in (:block r1) [:envelope :message :next-key]))))
      (t/is (not (sut/bytes=
                  (get-in (:block r1) [:envelope :message :next-key])
                  (get-in (:block r2) [:envelope :message :next-key])))))))

(t/deftest forged-block-with-wrong-key-rejected
  (t/testing "block signed with wrong ephemeral key fails verification"
    (let [kp       (sut/generate-keypair "Ed25519")
          pub      (.getPublic kp)
          r0       (block/authority-block
                    [[:user "alice"]] [] []
                    (.getPrivate kp)
                    (.getPublic kp))
          ;; Forge a block with a random key instead of the ephemeral key
          rogue-kp (sut/generate-keypair "Ed25519")
          r1-forged (block/delegated-block
                     (:block r0) [] [] []
                     (.getPrivate rogue-kp)
                     (.getPublic rogue-kp))]
      (t/is (false?
             (block/verify-chain
              [(:block r0) (:block r1-forged)] (sut/encode-public-key pub)))))))

(t/deftest hex-round-trip
  (let [original (byte-array [0 1 127 -128 -1 42])
        hex      (sut/bytes->hex original)
        back     (sut/hex->bytes hex)]
    (t/is (= (seq original) (seq back)))
    (t/is (= "00017f80ff2a" hex))))

(t/deftest public-key-hex-round-trip
  (t/testing "generate keypair → export hex → import hex → keys match"
    (let [kp      (sut/generate-keypair "Ed25519")
          pub     (.getPublic kp)
          hex     (sut/export-public-key-hex pub)
          decoded (sut/import-public-key-hex hex)]
      (t/is (string? hex))
      (t/is (sut/bytes=
             (sut/encode-public-key pub)
             (sut/encode-public-key decoded))))))
