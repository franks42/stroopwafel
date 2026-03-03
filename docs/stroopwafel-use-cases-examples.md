# Stroopwafel Use Cases & Examples

## How Stroopwafel Works — The 30-Second Version

Stroopwafel is a capability token library. A token is a signed chain of
blocks, each containing Datalog facts, rules, and checks. The authorization
dance has three actors:

| Actor | Role | What they hold |
|-------|------|----------------|
| **Authority** | Mints the root token | Ed25519 root keypair |
| **Token holder** | Carries and optionally attenuates the token | Token (includes ephemeral proof key) |
| **Authorizer** | Makes the access decision | Root public key + local policy |

The core invariants:

- **Attenuation only**: anyone holding a token can append blocks, but
  appended blocks can only *restrict* — never expand — the token's authority.
  Checks must pass; new facts in delegated blocks are invisible to the
  authority scope.
- **Offline verification**: the authorizer needs only the root public key.
  No callback to the authority, no shared secret.
- **Sealed tokens**: optionally discard the proof key to prevent further
  attenuation. Irreversible.

The evaluation pipeline:

```
Token arrives → verify signature chain (crypto) → evaluate Datalog:
  1. Load authority block facts (scope #{0})
  2. Load each delegated block (scope #{0 N :authorizer})
  3. Fire rules to fixpoint (scoped per block)
  4. Check all checks (per block, must all pass)
  5. Evaluate authorizer policies (ordered allow/deny, first match wins)
  → Result: allow or deny
```

Facts are EDN vectors: `[:right "alice" :read "/data"]`. Rules derive new
facts. Checks assert invariants. Policies decide.

---

## Use Case 1: API Gateway → Microservice → Resource

### Scenario

A SaaS platform with a public API gateway fronting internal microservices.
Users authenticate at the gateway (OAuth/OIDC), which mints a Stroopwafel
token encoding the user's permissions. The token flows through internal
services, each attenuating it to the minimum needed for the next hop.

### Actors and Network Position

```
┌──────────┐      ┌─────────┐      ┌───────────────┐      ┌──────────┐
│  Client  │─────▶│ Gateway │─────▶│ Order Service │─────▶│ DB Proxy │
│ (browser)│      │(authority│      │ (attenuates)  │      │(authorizer│
│          │      │  mints)  │      │               │      │ decides) │
└──────────┘      └─────────┘      └───────────────┘      └──────────┘
```

- **Gateway**: holds the root keypair. After OAuth validation, mints a
  token encoding the user's roles and resource rights.
- **Order Service**: receives the token, attenuates it to only the DB
  operations this request needs, and forwards it.
- **DB Proxy**: holds the root public key. Authorizes the request by
  evaluating the token against its local policy (which resources, which
  operations, request-time constraints).

### Policy

- Users have roles. Roles grant operations on resources.
- The gateway encodes role-derived rights in the authority block.
- Each downstream service attenuates to the specific operation.
- The DB proxy enforces: correct resource, correct operation, token not
  expired, request amount within limit.

### Logical Structure

**Step 1 — Gateway mints token after OAuth:**

```clojure
;; Authority block: what the user can do
{:facts  [[:user "user-1234"]
          [:right "user-1234" :read  "orders"]
          [:right "user-1234" :write "orders"]
          [:right "user-1234" :read  "products"]]
 :checks [{:id    :check-expiry
           :query [[:time ?t]]
           :when  [(< ?t 1709337600000)]}]}  ;; 24h expiry
```

**Step 2 — Order Service attenuates to this request:**

```clojure
;; Delegated block: restrict to read on orders only
{:checks [{:id    :read-orders-only
           :query [[:right "user-1234" :read "orders"]]}]}
```

This check *must match* for the token to be valid — it constrains the
token to contexts where the authority granted `read` on `orders`. If
someone tries to use this attenuated token to write, the check fails.

**Step 3 — DB Proxy evaluates:**

```clojure
;; Authorizer context: what's happening right now
{:facts    [[:time 1709251300000]
            [:resource "orders"]
            [:operation :read]]
 :rules    [{:id   :authorized
             :head [:authorized ?u ?op ?r]
             :body [[:right ?u ?op ?r]
                    [:resource ?r]
                    [:operation ?op]]}]
 :policies [{:kind  :allow
             :query [[:authorized ?u :read "orders"]]}
            {:kind  :deny
             :query [[:user ?u]]}]}  ;; catch-all deny
```

Evaluation: authority facts + authorizer facts → rules fire →
`:authorized` derived → allow policy matches → **access granted**.

If the order service had tried to pass through a write operation, the
delegated block's check would fail before policies are even evaluated.

### Runnable REPL Session

```clojure
(require '[stroopwafel.core :as sw])

;; --- Setup ---
(def root-kp (sw/new-keypair))

;; --- Step 1: Gateway mints after OAuth ---
(def token
  (sw/issue
   {:facts  [[:user "user-1234"]
             [:right "user-1234" :read  "orders"]
             [:right "user-1234" :write "orders"]
             [:right "user-1234" :read  "products"]]
    :checks '[{:id    :check-expiry
               :query [[:time ?t]]
               :when  [(< ?t 1709337600000)]}]}
   {:private-key (:priv root-kp)}))

;; --- Step 2: Order Service attenuates ---
;; No key needed — whoever holds the token can attenuate
(def attenuated
  (sw/attenuate
   token
   {:checks [{:id    :read-orders-only
              :query [[:right "user-1234" :read "orders"]]}]}))

;; --- Step 3: DB Proxy verifies + evaluates ---
(sw/verify attenuated {:public-key (:pub root-kp)})
;; => true

(sw/evaluate attenuated
  :authorizer
  {:facts    [[:time 1709251300000]
              [:resource "orders"]
              [:operation :read]]
   :rules    '[{:id   :authorized
                :head [:authorized ?u ?op ?r]
                :body [[:right ?u ?op ?r]
                       [:resource ?r]
                       [:operation ?op]]}]
   :policies '[{:kind  :allow
                :query [[:authorized "user-1234" :read "orders"]]}
               {:kind  :deny
                :query [[:user ?u]]}]})
;; => {:valid? true}

;; --- What if the attenuated token is used for a write? ---
(sw/evaluate attenuated
  :authorizer
  {:facts    [[:time 1709251300000]
              [:resource "orders"]
              [:operation :write]]
   :policies '[{:kind  :allow
                :query [[:authorized "user-1234" :write "orders"]]}]})
;; => {:valid? false}
;; The delegated block's check demands [:right "user-1234" :read "orders"]
;; which still matches, but the authorizer policy looks for :write
;; authorization — no rule derives it for :write + the attenuated token.
```

---

## Use Case 2: IoT Device Provisioning

### Scenario

A factory provisions IoT sensors. Each sensor receives a root-signed token
at manufacture, scoped to its device ID and permitted telemetry operations.
When deployed, the field installer attenuates the token to the specific
site and data channel. The cloud ingestion endpoint authorizes uploads.

### Actors and Network Position

```
┌──────────┐      ┌───────────┐      ┌──────────────┐      ┌──────────┐
│ Factory  │─────▶│  Field    │─────▶│   Sensor     │─────▶│  Cloud   │
│ (authority│      │ Installer │      │  (carries    │      │ Ingest   │
│  mints)  │      │(attenuates│      │   token)     │      │(authorizer│
│          │      │ to site)  │      │              │      │ decides) │
└──────────┘      └───────────┘      └──────────────┘      └──────────┘
```

- **Factory**: holds root keypair. Mints one token per device at manufacture.
- **Field installer**: receives token (e.g., via secure provisioning USB),
  attenuates to the deployment site and seals it. The sensor can no longer
  attenuate — it can only present the token.
- **Sensor**: stores the sealed token. Includes it in every upload request.
- **Cloud ingestion**: holds root public key. Authorizes based on device ID,
  site, data channel, and upload size limits.

### Policy

- Factory grants device-level capabilities (device ID, permitted operations).
- Installer narrows to deployment-specific constraints (site, channel).
- Installer seals to prevent the sensor (or anyone who compromises it) from
  modifying the token.
- Cloud enforces: valid device, correct site, permitted channel, payload
  within size limit, token not revoked.

### Logical Structure

**Step 1 — Factory mints at manufacture:**

```clojure
{:facts  [[:device "sensor-4821"]
          [:capability "sensor-4821" :upload "telemetry"]
          [:capability "sensor-4821" :upload "diagnostics"]]
 :checks [{:id    :check-not-expired
           :query [[:time ?t]]
           :when  [(< ?t 1740000000000)]}]}  ;; ~1 year validity
```

**Step 2 — Installer attenuates + seals:**

```clojure
;; Restrict to site-7 telemetry channel only
{:checks [{:id    :site-restriction
           :query [[:site "site-7"]]}
          {:id    :telemetry-only
           :query [[:capability "sensor-4821" :upload "telemetry"]]}]}
;; Then seal — sensor cannot further attenuate
```

**Step 3 — Cloud evaluates upload request:**

```clojure
{:facts    [[:time 1709300000000]
            [:site "site-7"]
            [:channel "telemetry"]
            [:payload-size 4096]]
 :rules    '[{:id   :upload-ok
              :head [:upload-authorized ?dev ?ch]
              :body [[:capability ?dev :upload ?ch]
                     [:channel ?ch]]}]
 :checks   '[{:id    :max-payload
              :query [[:payload-size ?s]]
              :when  [(<= ?s 65536)]}]
 :policies [{:kind  :allow
             :query [[:upload-authorized "sensor-4821" "telemetry"]]}
            {:kind  :deny
             :query [[:device ?d]]}]}
```

### Runnable REPL Session

```clojure
(require '[stroopwafel.core :as sw])

;; --- Factory provisioning ---
(def factory-kp (sw/new-keypair))

(def device-token
  (sw/issue
   {:facts  [[:device "sensor-4821"]
             [:capability "sensor-4821" :upload "telemetry"]
             [:capability "sensor-4821" :upload "diagnostics"]]
    :checks '[{:id    :check-not-expired
               :query [[:time ?t]]
               :when  [(< ?t 1740000000000)]}]}
   {:private-key (:priv factory-kp)}))

;; --- Field installer attenuates + seals ---
(def site-token
  (sw/attenuate
   device-token
   {:checks [{:id    :site-restriction
              :query [[:site "site-7"]]}
             {:id    :telemetry-only
              :query [[:capability "sensor-4821" :upload "telemetry"]]}]}))

(def sealed-token (sw/seal site-token))

(sw/sealed? sealed-token)
;; => true

;; Sensor stores sealed-token. Cannot attenuate further:
;; (sw/attenuate sealed-token {...}) => throws

;; --- Cloud ingestion authorizes upload ---
(sw/verify sealed-token {:public-key (:pub factory-kp)})
;; => true

;; Check revocation (application-level — compare against revocation set)
(sw/revocation-ids sealed-token)
;; => ["a1b2c3..." "d4e5f6..."]

(sw/evaluate sealed-token
  :authorizer
  {:facts    [[:time 1709300000000]
              [:site "site-7"]
              [:channel "telemetry"]
              [:payload-size 4096]]
   :rules    '[{:id   :upload-ok
                :head [:upload-authorized ?dev ?ch]
                :body [[:capability ?dev :upload ?ch]
                       [:channel ?ch]]}]
   :checks   '[{:id    :max-payload
                :query [[:payload-size ?s]]
                :when  [(<= ?s 65536)]}]
   :policies '[{:kind  :allow
                :query [[:upload-authorized "sensor-4821" "telemetry"]]}
               {:kind  :deny
                :query [[:device ?d]]}]})
;; => {:valid? true}

;; --- Wrong site? Denied. ---
(sw/evaluate sealed-token
  :authorizer
  {:facts    [[:time 1709300000000]
              [:site "site-99"]   ;; <-- wrong site
              [:channel "telemetry"]
              [:payload-size 4096]]
   :rules    '[{:id   :upload-ok
                :head [:upload-authorized ?dev ?ch]
                :body [[:capability ?dev :upload ?ch]
                       [:channel ?ch]]}]
   :policies '[{:kind  :allow
                :query [[:upload-authorized "sensor-4821" "telemetry"]]}]})
;; => {:valid? false}
;; Installer's check demands [:site "site-7"] — "site-99" doesn't match.
```

### Why Seal Matters Here

The sensor is a constrained device in a potentially hostile environment. If
an attacker compromises it, they get the token — but it's sealed:

- Cannot widen permissions (attenuation invariant)
- Cannot append blocks (sealed)
- Can only replay it — mitigated by the expiry check and revocation IDs

Without sealing, a compromised sensor could attenuate the token to add checks
that always pass (trivial checks), effectively laundering the token into a
clean carrier. Sealing closes this vector.

---

## Use Case 3: Cross-Organization Federation (Third-Party Blocks)

### Scenario

A healthcare portal lets patients share medical records with research
institutions. The hospital mints a data-access token. The patient's
identity provider (IdP) attests identity via a third-party block. The
research institution's data service authorizes access only when both the
hospital's grant and the IdP's attestation are present.

### Actors and Network Position

```
┌──────────┐                              ┌──────────────┐
│ Hospital │──── mints token ────────────▶│   Patient    │
│(authority)│                              │ (holds token)│
└──────────┘                              └──────┬───────┘
                                                 │
                    ┌──────────┐                 │ sends request
                    │   IdP    │◀── 3rd-party ───┘ to IdP
                    │(external │     request
                    │ signer)  │─── signed block ──┐
                    └──────────┘                   │
                                                   ▼
                                           ┌──────────────┐
                                           │  Research    │
                                           │  Data Service│
                                           │ (authorizer) │
                                           └──────────────┘
```

- **Hospital**: root authority. Mints a token granting access to specific
  records for a specific patient.
- **Patient**: token holder. Sends a third-party request to their IdP,
  receives a signed attestation block, appends it to the token, and
  presents the combined token to the research service.
- **IdP**: external signer. Signs a block attesting the patient's identity.
  Never sees the full token — only the binding reference (`previous-sig`).
- **Research Data Service**: authorizer. Trusts the hospital's root key for
  record grants AND the IdP's key for identity attestation. Both must be
  present for access.

### Why Third-Party Blocks?

The hospital can't attest identity — that's the IdP's job. The IdP can't
grant record access — that's the hospital's job. Neither trusts the other
to make both claims. Third-party blocks let each party sign only what they're
authoritative for, and the authorizer composes both into a single decision.

Without third-party blocks, the alternatives are:

- **Authorizer calls IdP at runtime**: adds latency, availability dependency,
  and fails offline.
- **IdP issues a separate JWT**: now you have two tokens with no
  cryptographic binding between them — the authorizer must correlate them
  and hope they refer to the same session.
- **Hospital embeds IdP claims**: hospital must trust and proxy IdP data,
  becoming a single point of compromise.

### Policy

- Hospital grants access to specific records with operation constraints.
- IdP attests patient identity (email, NPI, verified status).
- Research service requires both: a valid record-access grant from the
  hospital AND a verified identity attestation from a trusted IdP.
- The IdP's attestation is bound to this specific token instance (replay
  prevention via `previous-sig`).

### Logical Structure

**Step 1 — Hospital mints token:**

```clojure
{:facts  [[:patient "patient-8832"]
          [:record-access "patient-8832" "dataset-A" :read]
          [:record-access "patient-8832" "dataset-B" :read]]
 :checks [{:id    :check-expiry
           :query [[:time ?t]]
           :when  [(< ?t 1709337600000)]}]}
```

**Step 2 — Patient requests IdP attestation:**

```clojure
;; Patient extracts request from token
;; => {:previous-sig <bytes>}  (binding reference)

;; Patient sends request to IdP. IdP signs a block:
{:facts [[:identity "patient-8832" "patient@hospital.org"]
         [:verified "patient-8832" :npi "1234567890"]]}
;; IdP never sees the token contents — only the previous-sig.
```

**Step 3 — Patient appends IdP block and presents to research service.**

**Step 4 — Research Data Service evaluates:**

```clojure
{:trusted-external-keys [idp-public-key]  ;; <-- trust the IdP
 :facts    [[:time 1709251300000]
            [:requested-dataset "dataset-A"]
            [:requested-operation :read]]
 :rules    '[{:id   :access-granted
              :head [:access-granted ?p ?ds ?op]
              :body [[:record-access ?p ?ds ?op]
                     [:identity ?p ?email]
                     [:verified ?p :npi ?npi]
                     [:requested-dataset ?ds]
                     [:requested-operation ?op]]}]
 :policies [{:kind  :allow
             :query [[:access-granted ?p "dataset-A" :read]]}
            {:kind  :deny
             :query [[:patient ?p]]}]}
```

The rule `:access-granted` requires facts from *three* sources:

- `[:record-access ...]` — from the hospital's authority block (scope `#{0}`)
- `[:identity ...]` and `[:verified ...]` — from the IdP's third-party
  block (trusted because IdP key is in `:trusted-external-keys`)
- `[:requested-dataset ...]` and `[:requested-operation ...]` — from the
  authorizer's own facts (scope `#{:authorizer}`)

All three must join for the rule to fire. Missing any one → no
`:access-granted` fact → deny policy catches all.

### Runnable REPL Session

```clojure
(require '[stroopwafel.core :as sw])

;; --- Keypairs ---
(def hospital-kp (sw/new-keypair))   ;; Root authority
(def idp-kp (sw/new-keypair))        ;; Identity provider

;; --- Step 1: Hospital mints token ---
(def token
  (sw/issue
   {:facts  [[:patient "patient-8832"]
             [:record-access "patient-8832" "dataset-A" :read]
             [:record-access "patient-8832" "dataset-B" :read]]
    :checks '[{:id    :check-expiry
               :query [[:time ?t]]
               :when  [(< ?t 1709337600000)]}]}
   {:private-key (:priv hospital-kp)}))

;; --- Step 2: Patient requests IdP attestation ---
(def request (sw/third-party-request token))
;; => {:previous-sig <bytes>}

;; IdP signs a block (on IdP's system — they only see the request)
(def idp-block
  (sw/create-third-party-block
   request
   {:facts [[:identity "patient-8832" "patient@hospital.org"]
            [:verified "patient-8832" :npi "1234567890"]]}
   {:private-key (:priv idp-kp)
    :public-key  (:pub idp-kp)}))

;; --- Step 3: Patient appends and presents ---
(def combined-token (sw/append-third-party token idp-block))

(sw/verify combined-token {:public-key (:pub hospital-kp)})
;; => true

;; --- Step 4: Research service evaluates ---
(sw/evaluate combined-token
  :authorizer
  {:trusted-external-keys [(:pub idp-kp)]
   :facts    [[:time 1709251300000]
              [:requested-dataset "dataset-A"]
              [:requested-operation :read]]
   :rules    '[{:id   :access-granted
                :head [:access-granted ?p ?ds ?op]
                :body [[:record-access ?p ?ds ?op]
                       [:identity ?p ?email]
                       [:verified ?p :npi ?npi]
                       [:requested-dataset ?ds]
                       [:requested-operation ?op]]}]
   :policies '[{:kind  :allow
                :query [[:access-granted ?p "dataset-A" :read]]}
               {:kind  :deny
                :query [[:patient ?p]]}]})
;; => {:valid? true}

;; --- Without IdP trust, access denied ---
(sw/evaluate combined-token
  :authorizer
  {:facts    [[:time 1709251300000]
              [:requested-dataset "dataset-A"]
              [:requested-operation :read]]
   ;; No :trusted-external-keys — IdP facts invisible
   :rules    '[{:id   :access-granted
                :head [:access-granted ?p ?ds ?op]
                :body [[:record-access ?p ?ds ?op]
                       [:identity ?p ?email]
                       [:verified ?p :npi ?npi]
                       [:requested-dataset ?ds]
                       [:requested-operation ?op]]}]
   :policies '[{:kind  :allow
                :query [[:access-granted ?p "dataset-A" :read]]}
               {:kind  :deny
                :query [[:patient ?p]]}]})
;; => {:valid? false}
;; The :access-granted rule requires [:identity ...] and [:verified ...],
;; which come from the IdP's block. Without trusting the IdP key, those
;; facts are invisible — the rule never fires.

;; --- Replay prevention: IdP block bound to THIS token ---
(def other-token
  (sw/issue
   {:facts [[:patient "attacker"]]}
   {:private-key (:priv hospital-kp)}))

;; Attacker tries to graft the IdP block onto a different token
(def franken-token (sw/append-third-party other-token idp-block))

(sw/verify franken-token {:public-key (:pub hospital-kp)})
;; => false
;; The IdP signed against token's previous-sig, not other-token's.
;; Signature verification fails — the block is bound to the original token.
```

---

## Quick Reference: Stroopwafel API

| Function | Who calls it | What it does |
|----------|-------------|--------------|
| `new-keypair` | Authority, IdP | Generate Ed25519 keypair |
| `issue` | Authority | Mint root token with authority block |
| `attenuate` | Token holder | Append restricting block (no key needed) |
| `seal` | Token holder | Lock token against further attenuation |
| `verify` | Authorizer | Check signature chain integrity |
| `evaluate` | Authorizer | Run Datalog evaluation → allow/deny |
| `revocation-ids` | Authorizer | Extract per-block revocation hashes |
| `third-party-request` | Token holder | Create binding reference for external party |
| `create-third-party-block` | External party | Sign attestation block |
| `append-third-party` | Token holder | Attach signed block to token |

## Key Security Properties

| Property | Mechanism |
|----------|-----------|
| **Attenuation only** | Delegated block facts invisible to authority scope; checks can only add constraints |
| **Offline verification** | Ed25519 signature chain; authorizer needs only root public key |
| **Replay prevention** | Third-party blocks bound to specific token via `previous-sig` |
| **Revocation** | SHA-256 of block signatures; application maintains revocation set/bloom filter |
| **Sealed tokens** | Ephemeral key discarded; no further block appending possible |
| **Expiry** | `:when` guards on `[:time ?t]` facts; authorizer injects current time |
| **Scope isolation** | Block N sees only `#{0 N :authorizer}` — never other delegated blocks |
