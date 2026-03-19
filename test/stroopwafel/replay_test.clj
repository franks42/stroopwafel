(ns stroopwafel.replay-test
  (:require [stroopwafel.replay :as sut]
            [com.github.franks42.uuidv7.core :as uuidv7]
            [clojure.test :as t]))

(defn- uuidv7-with-ts
  "Create a UUIDv7-shaped UUID with a specific millisecond timestamp.
   The result passes uuidv7? validation."
  [ts-ms]
  (let [;; 48-bit timestamp in most-significant bits
        msb (bit-or (bit-shift-left (long ts-ms) 16)
                    ;; version 7 nibble + 12 random bits
                    0x7000
                    (bit-and (rand-int 0x1000) 0x0FFF))
        ;; variant 10 in top 2 bits + 62 random bits
        lsb (bit-or (bit-and (long (unchecked-long (* (Math/random) Long/MAX_VALUE)))
                             0x3FFFFFFFFFFFFFFF)
                    (unchecked-long 0x8000000000000000))]
    (java.util.UUID. msb lsb)))

(t/deftest fresh-request-id-passes
  (t/testing "a fresh UUIDv7 request-id passes all checks"
    (let [guard (sut/create-replay-guard)
          rid   (str (uuidv7/uuidv7))]
      (t/is (nil? (sut/check guard rid))))))

(t/deftest stale-request-id-rejected
  (t/testing "a request-id older than the freshness window is rejected"
    (let [guard (sut/create-replay-guard :freshness-ms 1000)
          old-ts (- (System/currentTimeMillis) 2000)
          rid    (str (uuidv7-with-ts old-ts))]
      (t/is (some? (sut/check-freshness guard rid)))
      (t/is (re-find #"too old" (sut/check-freshness guard rid))))))

(t/deftest future-request-id-rejected
  (t/testing "a request-id >5s in the future is rejected"
    (let [guard     (sut/create-replay-guard)
          future-ts (+ (System/currentTimeMillis) 10000)
          rid       (str (uuidv7-with-ts future-ts))]
      (t/is (some? (sut/check-freshness guard rid)))
      (t/is (re-find #"future" (sut/check-freshness guard rid))))))

(t/deftest replay-of-same-id-rejected
  (t/testing "replaying the same request-id is rejected"
    (let [guard (sut/create-replay-guard)
          rid   (str (uuidv7/uuidv7))]
      (t/is (nil? (sut/check guard rid)))
      (t/is (some? (sut/check guard rid)))
      (t/is (re-find #"Replay" (sut/check guard rid))))))

(t/deftest two-different-ids-both-pass
  (t/testing "two distinct request-ids both pass"
    (let [guard (sut/create-replay-guard)
          rid1  (str (uuidv7/uuidv7))
          rid2  (str (uuidv7/uuidv7))]
      (t/is (nil? (sut/check guard rid1)))
      (t/is (nil? (sut/check guard rid2))))))

(t/deftest eviction-removes-old-entries
  (t/testing "evict-expired! removes entries older than freshness window"
    (let [guard (sut/create-replay-guard :freshness-ms 50)
          rid   (str (uuidv7/uuidv7))]
      ;; Add entry
      (sut/check-replay guard rid)
      (t/is (= 1 (count @(:cache guard))))
      ;; Wait for it to expire
      (Thread/sleep 60)
      (sut/evict-expired! guard)
      (t/is (= 0 (count @(:cache guard)))))))

(t/deftest invalid-request-id-rejected
  (t/testing "non-UUIDv7 strings are rejected"
    (let [guard (sut/create-replay-guard)]
      (t/is (some? (sut/check-freshness guard "not-a-uuid")))
      ;; Valid UUID but not UUIDv7 (v4)
      (t/is (some? (sut/check-freshness guard (str (java.util.UUID/randomUUID))))))))
