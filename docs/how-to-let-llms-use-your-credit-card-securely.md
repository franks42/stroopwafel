# How to Let LLMs Use Your Credit Card Securely

## The Problem

AI assistants are moving from "answer questions" to "take actions": buy
groceries, trade stocks, pay bills, book flights. This requires giving
them access to financial instruments — credit cards, bank accounts,
brokerage APIs. The prospect is terrifying for good reasons:

- LLMs hallucinate. They confuse context, misinterpret instructions, and
  confidently act on wrong information.
- LLMs are manipulable. Prompt injection, jailbreaks, and adversarial
  inputs can redirect an agent's intent.
- LLMs have no accountability. When an AI buys 10,000 shares of a penny
  stock because it "seemed like a good idea," there's no one to fire.
- LLMs lose context. Long conversations degrade coherence. An agent that
  understood your preferences at turn 1 may be operating on noise by
  turn 200.

The naive approach — give the AI your credentials and let it call APIs
directly — is the digital equivalent of handing your credit card to a
stranger and saying "buy what you think I need." No sane security
architecture works this way.

This document proposes an architecture where **AI agents can initiate
transactions but never execute them**, using capability-based
authorization tokens as the bridge between the AI realm and the
deterministic execution realm.

---

## Core Principle: Separation of Intent and Execution

The architecture rests on one invariant:

> **No single AI can both decide to act AND execute the action.**

This is dual-control — the same principle behind:
- Traders cannot settle their own trades (front office / back office split)
- Developers cannot deploy to production without review (CI/CD gates)
- Nuclear launches require two independent keys (two-person integrity)
- Bank wire transfers above thresholds require dual authorization

Applied to AI agents:

| Concern | Who handles it | Properties |
|---------|---------------|------------|
| **Forming intent** | Agent AI | Probabilistic, creative, context-aware, fallible |
| **Evaluating intent** | Panel of AI judges | Independent, redundant, policy-aware |
| **Issuing capability** | Deterministic signing service | Predictable, auditable, cryptographic |
| **Executing transaction** | Deterministic execution service | Policy-enforcing, verifiable, no AI |

The capability token is the **only artifact that crosses the boundary**
from the AI realm to the execution realm. It is cryptographically signed,
time-limited, scope-constrained, and verifiable by deterministic code.

---

## Architecture

```
┌──────────────────────── AI REALM ─────────────────────────┐
│                                                            │
│  ┌────────────┐   structured   ┌────────────────────────┐ │
│  │  Agent AI  │───────────────▶│   Panel of AI Judges    │ │
│  │ (requester)│    intent      │  (independent models,   │ │
│  │            │                │   evaluate against      │ │
│  │            │◀───────────────│   user's standing       │ │
│  │            │    verdict     │   policy)               │ │
│  └─────┬──────┘  (structured)  └────────────────────────┘ │
│        │                                                   │
└────────┼───────────────────────────────────────────────────┘
         │ presents capability token
         ▼
┌──────────────────── DETERMINISTIC REALM ──────────────────┐
│                                                            │
│  ┌────────────────┐  token  ┌──────────────────────────┐  │
│  │ Signing Service│────────▶│   Execution Service      │  │
│  │ (mints token   │         │  (shopping, trading,     │  │
│  │  from verdict) │         │   payments)              │  │
│  │                │         │                          │  │
│  │ NOT an AI.     │         │  Verifies token against  │  │
│  │ Deterministic  │         │  hard policy. Executes   │  │
│  │ code only.     │         │  only with valid cap.    │  │
│  └────────────────┘         └──────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Phase 1: Intent Declaration

The agent AI wants to perform an action. It expresses this as a
**structured intent** — not prose, not an argument, not a persuasive
explanation. A machine-readable declaration of what, how much, from
where, and why.

```clojure
{:action      :purchase
 :vendor      "amazon.com"
 :item-id     "ASIN:B08X7JK34L"
 :item-name   "Clean Code (Robert C. Martin)"
 :category    :books
 :price       29.99
 :currency    :USD
 :quantity    1
 :goal-ref    "user-goal:learn-programming"
 :urgency     :normal
 :agent-id    "agent-session-7721"
 :timestamp   1709251200000}
```

Why structured, not argumentative? Because if the panel evaluates
persuasive prose, a sufficiently capable agent can craft arguments
that sound reasonable but are wrong. "I need to buy this cryptocurrency
because the user's portfolio is underweight in digital assets and this
token is about to appreciate 10x based on my analysis..." A structured
intent is verifiable against policy; a persuasive argument is not.

The agent AI never touches credentials, payment instruments, or
execution APIs. It cannot. They do not exist in its tool set. The
only action available to it is: submit an intent.

### Phase 2: Panel Evaluation

The intent goes to a panel of independent AI judges. Each judge
evaluates the intent against the user's standing policy (a structured
document, not AI-generated):

**What each judge checks:**

- Does this intent conform to the user's category whitelist/blacklist?
- Is the amount within single-transaction and daily-budget limits?
- Is the vendor on the approved list (or not on a blocked list)?
- Does the stated goal reference a real user-declared goal?
- Is this consistent with the user's historical patterns?
- Does anything about this intent look like prompt injection,
  social engineering, or adversarial manipulation?
- Would a reasonable person with this user's stated preferences
  approve this purchase?

**What each judge produces:**

```clojure
{:judge-id    "judge-2-claude"
 :verdict     :approve          ;; or :deny
 :constraints {:max-price 31.49 ;; 5% tolerance
               :expiry-ms 900000} ;; 15 minutes
 :reasoning   "Within budget, approved category, matches stated goal."
 :flags       []}               ;; or [:unusual-vendor :high-frequency]
```

The verdicts are collected by a deterministic aggregation service
(not AI). If the quorum is met (e.g., 2 of 3 approve), the
aggregated verdict proceeds to signing.

**Panel design principles:**

- **Heterogeneous models.** Different LLM providers, different model
  versions, different evaluation prompts. Correlated hallucinations
  across heterogeneous judges are unlikely.
- **No communication between judges.** Each evaluates independently.
  No deliberation, no consensus-building, no groupthink.
- **Judges never execute.** They produce verdicts. They have no access
  to payment APIs, credentials, or execution services.
- **Judges see the policy, not each other's verdicts.** Prevents
  anchoring bias.

### Phase 3: Capability Token Issuance

A **deterministic signing service** — not an AI — translates the
aggregated verdict into a cryptographically signed capability token.
This service is simple, auditable, and predictable:

```
IF   verdict.approved
AND  quorum_met(verdicts, policy.quorum)
AND  intent.amount <= policy.max_single_tx
AND  daily_spend + intent.amount <= policy.max_daily_spend
AND  intent.category IN policy.approved_categories
THEN sign_capability_token(intent, constraints)
ELSE reject
```

The signing service holds the root private key. No AI has access to
this key. The service performs redundant policy checks (belt and
suspenders — the panel checked policy too, but the signing service
enforces hard limits regardless of what the panel says).

The resulting token (using Stroopwafel as the capability framework):

```clojure
;; Authority block — what this capability authorizes
(stroopwafel.core/issue
 {:facts  [[:approved-purchase "ASIN:B08X7JK34L" "Clean Code" 29.99 :books]
           [:requester "agent-session-7721"]
           [:panel-verdict :approved 2 3]
           [:budget-remaining 470.01]
           [:vendor "amazon.com"]]
  :checks '[{:id    :expiry
             :query [[:time ?t]]
             :when  [(< ?t 1709252100000)]}      ;; 15-minute window
            {:id    :price-ceiling
             :query [[:execution-price ?p]]
             :when  [(<= ?p 31.49)]}             ;; 5% price tolerance
            {:id    :single-use
             :query [[:execution-id ?eid]]}]}     ;; must present execution ID
 {:private-key root-sk})
```

The token is handed to the agent AI. The agent cannot modify the
authority block (attenuation can only add restrictions, never expand
authority). The agent presents this token to the execution service.

### Phase 4: Execution

The execution service is a deterministic application — an API gateway,
a shopping service, a brokerage adapter. It:

1. **Verifies the token** against the root public key (signature chain)
2. **Checks revocation** against a revocation set/bloom filter
3. **Evaluates the token** against its own hard policy (authorizer):

```clojure
(stroopwafel.core/evaluate token
  :authorizer
  {:facts    [[:time (System/currentTimeMillis)]
              [:execution-price 29.99]
              [:execution-id (random-uuid)]
              [:vendor-status "amazon.com" :approved]
              [:daily-spend-so-far 29.99]]
   :rules    '[{:id   :within-budget
                :head [:budget-ok ?remaining]
                :body [[:budget-remaining ?remaining]
                       [:daily-spend-so-far ?spent]]
                :when [(<= ?spent ?remaining)]}]
   :policies '[{:kind  :allow
                :query [[:approved-purchase ?asin ?name ?price ?cat]
                        [:vendor-status ?vendor :approved]
                        [:budget-ok ?remaining]]}
               {:kind  :deny
                :query [[:requester ?r]]}]})
```

If valid → execute the purchase. If not → reject. The execution
service has no opinion, no reasoning, no judgment. It is a policy
enforcement point that either permits or denies based on cryptographic
verification and Datalog evaluation.

The AI never had access to the payment API. The AI never held
credentials. The AI held a capability token — a signed, time-limited,
scope-constrained permission slip that proves a panel of independent
judges reviewed the intent and a deterministic signing service
approved it against the user's policy.

---

## The User's Standing Policy

The user configures their policy once and updates it deliberately
(not through AI suggestions). The policy is the root authority — no
AI modifies it.

```clojure
{;; Spending limits
 :max-daily-spend       500
 :max-single-tx         100
 :currency              :USD

 ;; Category controls
 :approved-categories   #{:groceries :books :household :electronics}
 :blocked-categories    #{:alcohol :weapons :gambling :adult
                          :subscriptions :cryptocurrency}

 ;; Vendor controls
 :approved-vendors      #{"amazon.com" "costco.com" "target.com"}
 :blocked-vendors       #{}   ;; empty = no vendor blocklist
 :allow-new-vendors     false ;; require human approval for first-time vendors

 ;; Panel configuration
 :require-panel         true
 :panel-size            3
 :panel-quorum          2     ;; 2 of 3 must approve

 ;; Escalation thresholds
 :auto-approve-below    10    ;; trivial purchases skip the panel
 :human-approval-above  75    ;; high-value requires human confirmation
 :human-approval-categories #{:electronics :travel}

 ;; Agent constraints
 :max-daily-transactions 20
 :cooldown-minutes       5    ;; minimum time between transactions
 :require-goal-ref       true ;; every intent must reference a user-declared goal}
```

This policy lives in the deterministic realm. It is not generated,
interpreted, or modified by any AI. Changes require the user's direct
authentication (not their AI agent's).

---

## Escalation: When Humans Must Decide

Not everything should be delegated to the panel. The policy defines
escalation thresholds:

| Scenario | Action |
|----------|--------|
| Amount < $10 | Auto-approve (skip panel) |
| $10 ≤ amount < $75 | Panel decides |
| Amount ≥ $75 | Panel + human confirmation |
| First-time vendor | Human confirmation regardless of amount |
| Blocked category | Reject (no escalation) |
| Unusual pattern (flagged by judge) | Human confirmation |
| Daily budget exhausted | Reject (no escalation) |

Human confirmation is a notification + approval flow outside the AI
realm entirely — push notification, email, SMS with one-time code.
The human's approval is a separate signed assertion (potentially a
third-party block) that the signing service requires before minting
the token.

```clojure
;; Human approval as a third-party block on the capability token
(def human-block
  (stroopwafel.core/create-third-party-block
   request
   {:facts [[:human-approved "purchase-req-4481" "user-frank"]]}
   {:private-key user-approval-sk
    :public-key  user-approval-pk}))

;; Execution service trusts the human approval key
(stroopwafel.core/evaluate token
  :authorizer
  {:trusted-external-keys [user-approval-pk]
   :checks [{:id    :needs-human
             :query [[:human-approved ?req-id ?user]]}]
   ...})
```

---

## Threat Model

### Threats addressed

| Threat | Mitigation |
|--------|-----------|
| **Agent hallucination** (buys wrong item, wrong quantity) | Panel cross-checks intent against policy and patterns |
| **Agent manipulation** (prompt injection redirects purchase) | Structured intents, not prose; panel detects anomalies |
| **Credential theft** (AI leaks payment info) | AI never has credentials; capability token ≠ credential |
| **Single point of failure** (one bad AI decision) | Dual-control: panel quorum + signing service + execution policy |
| **Scope creep** (AI gradually expands its authority) | User policy is immutable by AI; capabilities are per-transaction |
| **Replay attacks** (reuse a capability token) | Time-limited tokens, single-use execution IDs, revocation |
| **Token theft** (attacker steals capability) | Short expiry (15 min), sealed tokens, specific item/price |
| **Budget exhaustion** (many small legitimate purchases) | Daily limits, transaction rate limits, cooldown periods |

### Threats NOT fully addressed

| Threat | Residual risk |
|--------|--------------|
| **Adversarial intent crafting** | Agent constructs intents that are technically policy-compliant but substantively wrong (e.g., buying items for resale, gift card laundering). Panel judges may catch this based on pattern analysis, but sophisticated adversarial intents within policy bounds are the hard problem. |
| **Panel collusion** | If all panel judges run the same model from the same provider, a model-level vulnerability affects all judges simultaneously. Mitigation: heterogeneous models from different providers. |
| **Slow-burn manipulation** | An agent that makes 100 small, reasonable purchases to build a pattern, then exploits that pattern for one large bad purchase. Mitigation: anomaly detection in the panel, human review of transaction history. |
| **Social engineering the user** | Agent convinces the user to raise spending limits or approve a vendor. Outside the technical architecture — this is a UX/education problem. |

---

## Why Capabilities (Not Permissions or Roles)

Capability tokens are the right primitive for this architecture because:

**Bearer model.** The AI presents the token; the execution service
validates it. No identity lookup, no session management, no "who is
this AI and what role does it have?" The token carries its own authority.

**Attenuation.** The signing service can mint a broad capability; the
AI (or any intermediary) can only narrow it further. A token for
"buy anything under $100" can be attenuated to "buy this specific
book for $29.99" but never widened to "buy anything under $200."

**Offline verification.** The execution service needs only the root
public key. No callback to the signing service, no real-time check
against a permission database. This matters for reliability — the
execution service works even if the signing service is temporarily
down (for tokens already issued).

**Per-transaction scoping.** Each capability is minted for a specific
intent. There is no persistent "agent has shopping permission" state
that could be exploited. The permission exists only as long as the
token is valid (minutes, not hours or days).

**Cryptographic audit trail.** Every token has revocation IDs. Every
evaluation can produce an explain tree. The chain of intent →
verdict → token → execution is fully traceable.

**Sealing.** Once the signing service mints the token, it can be
sealed — preventing the AI from appending any blocks (even
attenuating ones). The token is frozen: this specific permission,
this specific constraint, take it or leave it.

---

## Comparison with Alternative Approaches

### OAuth Scopes / API Keys

Traditional approach: give the AI an API key with scoped permissions
("can make purchases under $100"). Problems:

- The key is a **persistent credential** — if leaked, the attacker
  has ongoing access until revoked.
- Scope is coarse — "purchases under $100" can't constrain to specific
  items, vendors, or daily budgets without server-side state.
- No dual-control — the AI decides and executes with the same key.
- No cryptographic proof of *why* a purchase was approved.

### Smart Contract Allowances (DeFi pattern)

In DeFi, users grant token allowances to smart contracts: "this
contract can spend up to N of my tokens." Problems:

- Allowances are persistent and amount-based, not per-transaction.
- No semantic review of *what* is being purchased — only *how much*.
- No human-in-the-loop escalation.
- Revocation requires an on-chain transaction (slow, costs gas).

### Agent-Specific Credentials (Virtual Cards)

Issue a virtual credit card with low limits for AI use. Better than
raw credentials, but:

- Still a persistent credential (the card number).
- Policy enforcement is at the card issuer level (crude: amount limits,
  merchant category codes). Can't express "only buy items the user has
  explicitly declared as goals."
- No panel review, no dual-control.
- If the AI agent is compromised, the attacker has a working card number.

### The Capability Approach (This Document)

- Per-transaction, time-limited, cryptographically signed.
- Dual-control: AI proposes, panel reviews, deterministic service signs.
- Rich policy expressible in Datalog (category, vendor, price, budget,
  goal reference, time, rate limits).
- No persistent credential in the AI's possession.
- Cryptographic audit trail (intent → verdict → token → execution).
- Offline verification at the execution service.

---

## Mapping to Stroopwafel

| Concept | Stroopwafel primitive |
|---------|---------------------|
| User's standing policy | Root authority configuration (input to signing service) |
| Approved intent | Authority block facts + checks |
| Panel verdict | Third-party block (signed by panel service key) |
| Human approval | Third-party block (signed by user's approval key) |
| Per-transaction constraints | `:when` guards (price ceiling, time expiry, budget) |
| Execution service policy | Authorizer (`:facts`, `:rules`, `:policies`) |
| Single-use enforcement | Execution ID check + revocation after use |
| Emergency stop | Revoke the signing service's key or all issued tokens |
| Audit trail | `revocation-ids` + `evaluate :explain? true` |
| Frozen permissions | `seal` — prevent any further token modification |

The third-party block model is particularly apt for this architecture:
the panel's verdict is a signed block bound to a specific intent (via
`previous-sig` — replay prevention). The execution service trusts the
panel's key for verdict assertions but not for anything else. The
human approval (when required) is a second third-party block from the
user's own key.

---

## Open Questions

1. **Panel economics.** Running 3+ LLM evaluations per transaction
   adds cost and latency. For a $5 grocery item, is the panel overhead
   justified? The auto-approve threshold for trivial purchases helps,
   but the right threshold is use-case dependent.

2. **Intent specification language.** The structured intent format
   shown above is ad hoc. A standardized intent schema — covering
   purchases, payments, trades, subscriptions, reservations — would
   make the architecture portable across execution services.

3. **Panel judge prompt security.** The judges evaluate intents that
   originate from a potentially compromised agent AI. If the intent
   contains adversarial content designed to manipulate the judges
   (indirect prompt injection), the panel itself could be compromised.
   Structured intents (not freeform text) mitigate this, but intent
   fields like "goal-ref" or "item-name" could still carry payloads.

4. **Cross-agent coordination.** If a user has multiple AI agents
   (shopping agent, travel agent, finance agent), they share a daily
   budget. The signing service must track aggregate spend across
   agents — a stateful concern that capability tokens alone don't solve.

5. **Regulatory compliance.** Financial regulations (PSD2, PCI-DSS)
   may require specific authentication flows (SCA, 3D Secure) that
   don't map cleanly to capability tokens. The execution service may
   need to bridge between the capability model and regulated payment
   flows.

6. **Liability.** When the AI buys the wrong thing despite panel
   approval, who is liable? The architecture provides a clear audit
   trail (intent → verdicts → token → execution), but the legal
   framework for AI-initiated transactions is nascent.

---

## Prior Art and Related Work

### The Authorization Crisis Is Universally Acknowledged

Multiple industry bodies have identified that traditional IAM (OAuth,
OIDC, RBAC, SAML) is fundamentally inadequate for agentic AI:

- **ISACA: "The Looming Authorization Crisis"** (Dec 2025) — OAuth 2.0 and
  OIDC were designed for deterministic apps with single authenticated
  principals. Agents violate every assumption: ephemeral sessions, sub-agent
  creation, multi-principal delegation. Capability-based authorization is
  essentially what ISACA is calling for.
  https://www.isaca.org/resources/news-and-trends/industry-news/2025/the-looming-authorization-crisis-why-traditional-iam-fails-agentic-ai

- **Cloud Security Alliance: "Authorization Outlives Intent"** (Feb 2026) —
  Introduces "authorization drift": credentials outliving their workflows.
  Non-human identities outnumber humans 144:1. EU AI Act Article 14
  (Aug 2026) requires proof that every AI-driven action was authorized at
  execution time. Short-lived sealed capability tokens directly address this.
  https://cloudsecurityalliance.org/blog/2026/02/25/ai-security-when-authorization-outlives-intent

- **OWASP Top 10 for Agentic Applications** (Dec 2025, 100+ experts) —
  New principle: **"Least Agency"** — autonomy should be earned, not a
  default. ASI03 (Identity & Privilege Abuse) is exactly what capability
  tokens with attenuation address: each delegation step can only narrow,
  never widen.
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

- **Gravitee: State of AI Agent Security 2026** — Only 14.4% of orgs have
  all AI agents go live with full security approval. 80% report risky agent
  behaviors (unauthorized access, improper data exposure).
  https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control

### Standards Bodies Are Actively Soliciting Input

- **NIST AI Agent Standards Initiative** (Feb 2026) — Three pillars:
  agent standards, open source protocols, and agent security/identity
  research. RFI on AI Agent Security due March 9, 2026. AI Agent Identity
  and Authorization Concept Paper due April 2, 2026.
  https://www.nist.gov/caisi/ai-agent-standards-initiative

### Runtime Enforcement Frameworks

These operate at the guardrail layer — they could consume capability
tokens as input but don't produce or verify them:

- **AgentSpec** (ICSE 2026, Singapore Mgmt Univ) — DSL for runtime
  constraints on LLM agents. Rules with triggers, predicates, and
  enforcement. Prevents unsafe executions in 90%+ of cases. Complementary
  to capability tokens: AgentSpec enforces, tokens authorize.
  https://arxiv.org/abs/2503.18666

- **Agent Behavioral Contracts (ABC)** (Feb 2026) — Design-by-Contract
  for AI agents. C = (Preconditions, Invariants, Governance, Recovery).
  Contracted agents detect 5.2–6.8 violations per session that uncontracted
  agents miss. Recovery ranges from prompt modification through autonomy
  reduction to human escalation.
  https://arxiv.org/abs/2602.22302

- **Agent Contracts** (Jan 2026) — Extends ABC with resource-bounded
  execution: multi-dimensional resource constraints and temporal boundaries.
  Maps naturally to capability token attenuation (spending budgets, time
  windows).
  https://arxiv.org/abs/2601.08815

### Multi-Agent Verification (Panel-of-Judges Validation)

The academic literature validates multi-agent evaluation but applies it to
content quality and safety — not to transaction authorization:

- **Multi-Agent Debate for LLM Safety** (Nov 2025) — Structured debate
  among critic, defender, and judge agents. The role pattern could be
  adapted for financial transaction approval.
  https://arxiv.org/pdf/2511.06396

- **Agent-as-a-Judge Survey** (Jan 2026) — Documents horizontal debate
  mechanisms leveraging diverse perspectives to counteract single-evaluator
  bias.
  https://arxiv.org/pdf/2601.05111

- **Multi-Agent Debate with Adaptive Stability Detection** (Oct 2025) —
  Mathematical proof that multi-agent debate outperforms static ensembles.
  https://arxiv.org/html/2510.12697v1

- **Auditing Multi-Agent Reasoning Trees** (Feb 2026) — Auditing
  multi-agent reasoning trees outperforms both majority vote and
  LLM-as-Judge approaches.
  https://arxiv.org/html/2602.09341

Applying multi-agent verification to transaction authorization (where
judges evaluate whether a financial action should be approved given
capability constraints) appears to be a **novel application area**.

### Industry Approaches to Agent Permissions

- **Anthropic MCP + OAuth 2.1** — Standardizes agent-to-tool
  connections with OAuth 2.1/PKCE. Handles authentication and coarse
  authorization but not capability delegation, attenuation, or bearer
  tokens. Identity-centric, not capability-centric. Donated to the
  Agentic AI Foundation (Linux Foundation, Dec 2025).
  https://modelcontextprotocol.io/specification/draft/basic/authorization

- **Visa Trusted Agent Protocol** (Oct 2025) — Ecosystem framework for
  AI commerce, built on HTTP Message Signatures. Partners: Cloudflare,
  Stripe, Shopify, Coinbase, et al. Focuses on agent-to-merchant identity
  verification, not capability restriction. Implements a form of intent
  separation: agents express structured intents rather than executing
  checkout directly.
  https://usa.visa.com/about-visa/newsroom/press-releases.releaseId.21716.html

- **Oso** — Policy-as-code (Polar language), fine-grained RBAC/ReBAC/ABAC.
  Gates what data an agent can access. No cryptographic delegation or
  attenuation.
  https://www.osohq.com/learn/best-practices-of-authorizing-ai-agents

- **CyberArk Secure AI Agents** — First purpose-built identity security
  for AI agents with privilege controls. Traditional IAM (identity-centric),
  not capability-centric.
  https://www.cyberark.com/press/cyberark-introduces-first-identity-security-solution-purpose-built-to-protect-ai-agents-with-privilege-controls/

- **OPA + MCP Gateway** — Least-privilege agent gateway using OPA
  policy-as-code with ephemeral runners. Policy evaluation engine that
  could consume capability tokens but doesn't produce them.
  https://www.infoq.com/articles/building-ai-agent-gateway-mcp/

### Blockchain/Crypto Approaches

- **ERC-8004: Trustless Agents** (Ethereum mainnet, Jan 2026) — On-chain
  Identity, Reputation, and Validation registries. "Know Your Agent" (KYA)
  framework. Handles agent identity and reputation, not capability
  restriction. Proposed by MetaMask, Ethereum Foundation, Google, Coinbase.
  https://eco.com/support/en/articles/13221214-what-is-erc-8004-the-ethereum-standard-enabling-trustless-ai-agents

- **x402 Payment Protocol** (Coinbase/Cloudflare) — Revives HTTP 402 for
  instant stablecoin payments. Handles payment execution, not authorization.
  Capability tokens could govern *whether* an agent may pay; x402 handles
  the payment mechanics.

- **Autonomous Agents on Blockchains** (Jan 2026) — Survey of 317 works.
  Five-part taxonomy: read-only analytics, intent generation, delegated
  execution, autonomous signing, multi-agent workflows. Threat model
  covering prompt injection, policy misuse, key compromise.
  https://arxiv.org/abs/2601.04583

- **Web3 AI Agent sector** — $4.3B, 282 projects building payment
  standards, identity frameworks, coordination layers. AI agents
  contributed 30% of trades on Polymarket by late 2025. Largely missing:
  capability-attenuation models.

- **Agent Security Bench (ASB)** (ICLR 2025) — Benchmark: 10 scenarios
  (including e-commerce, finance), 400+ tools, 27 attack/defense methods.
  Highest average attack success rate: 84.30%. Current defenses are
  inadequate. Cryptographic capability enforcement could reduce the attack
  surface by making unauthorized actions impossible rather than relying on
  prompt-level defenses.
  https://arxiv.org/abs/2410.02644

### The Intent/Execution Separation Is Emerging

- **Blockchain solver networks** — Agents declare intents (desired
  outcomes), solvers handle execution. Natural insertion point for
  capability tokens between intent and execution.
- **Visa TAP** — Structured intents + delegated authority.
- **Auton Framework** (Feb 2026) — Declarative architecture separating
  specification (what) from execution (how) for autonomous agents.
  https://arxiv.org/abs/2602.23720

### Gap Analysis

| Capability | Needed | Who has it |
|-----------|--------|-----------|
| Cryptographic capability attenuation | Yes | **Nobody for AI agents.** Biscuit/Stroopwafel have the primitive but haven't applied it to AI agent authorization. |
| Bearer tokens with delegation chains | Yes | Nobody. MCP uses OAuth (identity-centric). |
| Multi-agent transaction verification | Yes | Academic validation exists (debate, judge panels) but not applied to financial authorization. |
| Intent/execution separation | Yes | Emerging (Visa TAP, blockchain solvers, Auton) but without cryptographic capability enforcement. |
| Runtime policy enforcement | Yes | AgentSpec, ABC, OPA — but these enforce, they don't authorize with bearer tokens. |
| Agent identity/reputation | Partial | ERC-8004, CyberArk — necessary but not sufficient. |
| Short-lived, sealable tokens | Yes | Stroopwafel has this. Nobody else is applying it to AI agents. |

The convergence is clear: **everyone agrees the authorization problem
exists, nobody has combined cryptographic capability tokens with
multi-agent verification for AI agent transaction security.** The
building blocks exist separately — capability tokens (Biscuit/Stroopwafel),
multi-agent debate (academic), intent separation (emerging), runtime
enforcement (AgentSpec/OPA) — but the integrated architecture described
in this document appears to be novel.
