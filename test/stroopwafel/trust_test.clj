(ns stroopwafel.trust-test
  (:require [stroopwafel.trust :as sut]
            [stroopwafel.crypto :as crypto]
            [clojure.test :as t]))

(t/deftest single-key-produces-unscoped-fact
  (t/testing "a single PublicKey produces one unscoped trust fact"
    (let [kp    (crypto/generate-keypair "Ed25519")
          pub   (.getPublic kp)
          facts (sut/trust-root-facts pub)]
      (t/is (= 1 (count facts)))
      (t/is (= :trusted-root (first (first facts))))
      (t/is (= :any (nth (first facts) 2)))
      (t/is (= :any (nth (first facts) 3))))))

(t/deftest multi-root-map-produces-scoped-facts
  (t/testing "map with scoped entries produces cross-product facts"
    (let [pk-bytes (byte-array [1 2 3])
          facts    (sut/trust-root-facts
                    {pk-bytes {:scoped-to {:effects #{:read :write}
                                           :domains #{"market" "account"}}}})]
      ;; 2 effects × 2 domains = 4 facts
      (t/is (= 4 (count facts)))
      (t/is (every? #(= :trusted-root (first %)) facts))
      ;; All point to the same pk-bytes
      (t/is (every? #(identical? pk-bytes (second %)) facts)))))

(t/deftest unscoped-entry-in-map-produces-any-any
  (t/testing "map entry without :scoped-to produces :any :any"
    (let [pk-bytes (byte-array [4 5 6])
          facts    (sut/trust-root-facts {pk-bytes {}})]
      (t/is (= 1 (count facts)))
      (t/is (= [:trusted-root pk-bytes :any :any] (first facts))))))

(t/deftest nil-produces-empty-vector
  (t/testing "nil input produces empty vector"
    (t/is (= [] (sut/trust-root-facts nil)))))

(t/deftest empty-map-produces-empty-vector
  (t/testing "empty map produces empty vector"
    (t/is (= [] (sut/trust-root-facts {})))))
