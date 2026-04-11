(ns stroopwafel.pep-test
  "Tests for the PEP pipeline abstraction."
  (:require [clojure.test :refer [deftest is]]
            [stroopwafel.pep :as pep]))

(defn ring-req
  "Build a minimal ring request."
  ([method uri] (ring-req method uri nil))
  ([method uri body]
   (cond-> {:request-method method :uri uri :headers {}}
     body (assoc :body (pr-str body)))))

;; ---------------------------------------------------------------------------
;; Pipeline composition tests
;; ---------------------------------------------------------------------------

(deftest pipeline-exempt-passes-through
  (let [handler  (fn [_] {:status 200 :body "ok"})
        pep-fn   (pep/create-pep
                  {:canonicalize  (fn [_] {:method "get" :path "/test"})
                   :extract-creds (fn [_] {:token-str nil})
                   :authorize     (fn [& _] {:authorized false})
                   :exempt?       (fn [_] true)
                   :public-key    nil
                   :log-fn        (fn [_ _])})
        wrapped  (pep-fn handler)
        resp     (wrapped (ring-req :get "/anything"))]
    (is (= 200 (:status resp)))
    (is (= "ok" (:body resp)))))

(deftest pipeline-no-token-returns-401
  (let [handler (fn [_] {:status 200 :body "ok"})
        pep-fn  (pep/create-pep
                 {:canonicalize  (fn [_] {:method "get" :path "/test"})
                  :extract-creds (fn [_] {:token-str nil})
                  :authorize     (fn [& _] {:authorized false})
                  :exempt?       (fn [_] false)
                  :public-key    nil
                  :log-fn        (fn [_ _])})
        wrapped (pep-fn handler)
        resp    (wrapped (ring-req :get "/test"))]
    (is (= 401 (:status resp)))))

(deftest pipeline-deny-returns-403
  (let [handler (fn [_] {:status 200 :body "ok"})
        pep-fn  (pep/create-pep
                 {:canonicalize  (fn [_] {:method "get" :path "/test"
                                          :effect :read :domain "x"})
                  :extract-creds (fn [_] {:token-str "sometoken"})
                  :authorize     (fn [& _] {:authorized false
                                            :reason "nope"
                                            :reason-code :insufficient})
                  :exempt?       (fn [_] false)
                  :public-key    nil
                  :log-fn        (fn [_ _])})
        wrapped (pep-fn handler)
        resp    (wrapped (ring-req :get "/test"))]
    (is (= 403 (:status resp)))))

(deftest pipeline-allow-passes-to-handler
  (let [handler (fn [_] {:status 200 :body "ok"})
        pep-fn  (pep/create-pep
                 {:canonicalize  (fn [_] {:method "get" :path "/test"
                                          :effect :read :domain "x"})
                  :extract-creds (fn [_] {:token-str "sometoken"})
                  :authorize     (fn [& _] {:authorized true})
                  :exempt?       (fn [_] false)
                  :public-key    nil
                  :log-fn        (fn [_ _])})
        wrapped (pep-fn handler)
        resp    (wrapped (ring-req :get "/test"))]
    (is (= 200 (:status resp)))
    (is (= "ok" (:body resp)))))

(deftest pipeline-canonicalize-nil-passes-through
  (let [handler (fn [_] {:status 404 :body "not found"})
        pep-fn  (pep/create-pep
                 {:canonicalize  (fn [_] nil)
                  :extract-creds (fn [_] {:token-str nil})
                  :authorize     (fn [& _] {:authorized false})
                  :exempt?       (fn [_] false)
                  :public-key    nil
                  :log-fn        (fn [_ _])})
        wrapped (pep-fn handler)
        resp    (wrapped (ring-req :get "/unknown"))]
    (is (= 404 (:status resp)))))
