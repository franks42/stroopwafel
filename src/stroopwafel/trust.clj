(ns stroopwafel.trust
  "Trust-root fact generation for Datalog authorization.

   Converts trust-root configurations into [:trusted-root pk-bytes effect domain]
   facts suitable for Datalog evaluation."
  (:require [stroopwafel.crypto :as crypto]))

(defn trust-root-facts
  "Convert trust-roots config into Datalog facts.

   Accepts either:
   - A single PublicKey (unscoped — generates [:trusted-root pk-bytes :any :any])
   - A map of {pk-bytes → {:scoped-to {:effects #{...} :domains #{...}}}}
   - nil → []

   Returns vector of [:trusted-root pk-bytes effect domain] facts."
  [trust-roots]
  (cond
    ;; Single public key — trust for everything
    (and (not (map? trust-roots)) (not (nil? trust-roots)))
    (let [pk-bytes (crypto/encode-public-key trust-roots)]
      [[:trusted-root pk-bytes :any :any]])

    ;; Map of pk-bytes → scope
    (map? trust-roots)
    (into []
          (mapcat (fn [[pk-bytes {:keys [scoped-to]}]]
                    (if scoped-to
                      (for [effect (:effects scoped-to)
                            domain (:domains scoped-to)]
                        [:trusted-root pk-bytes effect domain])
                      ;; No scope = trust for everything
                      [[:trusted-root pk-bytes :any :any]])))
          trust-roots)

    :else []))
