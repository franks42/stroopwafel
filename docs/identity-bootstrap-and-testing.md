# Identity Bootstrap: From Directory Paths to OS Accounts

> Identity is a directory. The key lookup is always
> `{identity-dir}/.ssh/id_ed25519`. Same code path in testing
> and production — only the directory changes.

---

## The Principle

Every actor in the system — operator, agent, proxy — needs an
Ed25519 keypair. The question is where that keypair lives and
who controls access to it.

The answer is the same in all environments: **a directory with
an `.ssh/` subdirectory containing `id_ed25519` and
`id_ed25519.pub`.** This is the SSH convention that sysadmins
already know, already audit, and already rotate.

In production, the directory is an OS account home dir with
kernel-enforced file permissions. In testing, it's a project
subdirectory with the same structure. The code doesn't know
the difference — it just reads keys from a path.

---

## Testing Setup: Directory-as-Identity

Each test actor gets its own directory. The directory path IS
the identity:

```
~/dev/test/
├── operator/                    ← the authority (signs tokens)
│   └── .ssh/
│       ├── id_ed25519           ← operator sk
│       └── id_ed25519.pub       ← operator pk (= trust root)
│
├── agent-trader/                ← AI agent with trade access
│   └── .ssh/
│       ├── id_ed25519           ← trader sk (signs requests)
│       └── id_ed25519.pub       ← trader pk (bound in token)
│
├── agent-reader/                ← AI agent with read-only access
│   └── .ssh/
│       ├── id_ed25519           ← reader sk
│       └── id_ed25519.pub       ← reader pk
│
├── outbound-authority/          ← company's outbound policy authority
│   └── .ssh/
│       ├── id_ed25519           ← outbound authority sk
│       └── id_ed25519.pub       ← outbound authority pk
│
└── proxy/                       ← the resource server
    └── config/
        └── trust-roots.cedn     ← which pks to trust, fetched from operator
```

### Bootstrap Script

```bash
#!/bin/bash
# Create test identities — one ssh-keygen per actor
for actor in operator agent-trader agent-reader outbound-authority; do
  mkdir -p ~/dev/test/$actor/.ssh
  ssh-keygen -t ed25519 -f ~/dev/test/$actor/.ssh/id_ed25519 -N "" -q
done
```

That's it. No custom key formats, no key generation ceremonies,
no new tools to learn. Every identity is bootstrapped with a
single `ssh-keygen` call.

### Using Test Identities

```bash
# Operator issues a bound token for the trader agent
bb token issue \
  --identity ~/dev/test/operator \
  --agent-ssh-key ~/dev/test/agent-trader/.ssh/id_ed25519.pub \
  --effects read,write --domains market,trade

# Operator issues a read-only token for the reader agent
bb token issue \
  --identity ~/dev/test/operator \
  --agent-ssh-key ~/dev/test/agent-reader/.ssh/id_ed25519.pub \
  --effects read --domains market,account

# Agent signs requests using its own identity
STROOPWAFEL_IDENTITY=~/dev/test/agent-trader \
  bb api market/quote --symbol AAPL

# Proxy trusts the operator's public key
STROOPWAFEL_ROOT_KEY=$(cat ~/dev/test/operator/.ssh/id_ed25519.pub) \
  bb server:start
```

Same CLI, same code paths, same `stroopwafel.ssh/load-keypair`.
The `--identity` flag (or `STROOPWAFEL_IDENTITY` env var) just
sets the directory where keys are loaded from.

---

## Production Setup: OS Account-as-Identity

In production, the directories become OS accounts. The kernel
enforces what testing relies on convention for:

```
/home/
├── operator/                    ← human account, holds root sk
│   └── .ssh/
│       ├── id_ed25519           ← mode 0600, only operator can read
│       └── id_ed25519.pub       ← mode 0644, world-readable
│
├── agent-trader/                ← service account for AI agent
│   └── .ssh/
│       ├── id_ed25519           ← mode 0600, only agent can read
│       └── id_ed25519.pub       ← mode 0644, operator reads this
│
└── proxy/                       ← service account for proxy
    └── .alpaca/
        └── credentials          ← Alpaca API keys, mode 0600
```

### Security Properties

| Asset | Who can read | Enforcement |
|---|---|---|
| Operator sk | operator only | OS file permissions (0600) |
| Operator pk | anyone | It's public — that's the point |
| Agent sk | agent only | OS file permissions (0600) |
| Agent pk | anyone | Operator reads it to bind tokens |
| Proxy Alpaca keys | proxy only | OS file permissions (0600) |
| Tokens | agent reads, operator writes | Group permissions or sudo |

**Compromised agent** → attacker gets agent sk + bound token.
Token is useless without the sk. Sk is useless without a valid
token. But together they work — scope and time-limit tokens to
minimize blast radius.

**Compromised proxy** → attacker gets Alpaca API keys but NOT
the root sk. Can't mint new tokens. Can only use existing
connections until keys are rotated.

**Compromised operator** → worst case. Can mint new tokens.
Monitored via audit log. Rotate the root keypair, reissue all
tokens.

---

## Browser Identity: Ephemeral Keys via WebAuthn Delegation

For browser-based agents, the identity model extends with
ephemeral keypairs and SPKI delegation:

```
YubiKey / Secure Enclave          Browser tab
═══════════════════════           ═══════════

Long-lived sk                     Ephemeral sk
  hardware-bound                    in-memory only
  user touches ONCE                 no user interaction
                                    dies with the tab
        │
        │ signs delegation token
        │   [:authorized-agent-key ephemeral-pk]
        │   with expiry + scope
        ▼
  Stroopwafel token
        │
        │ browser attaches to every RPC message
        │ ephemeral sk signs each envelope
        ▼
  Server PEP verifies chain:
    WebAuthn root → delegation → ephemeral key → signed request
```

The browser generates the ephemeral keypair via Web Crypto API:

```javascript
const kp = await crypto.subtle.generateKey(
  { name: "Ed25519" },
  true,
  ["sign", "verify"]
);
// Extract pk bytes for the delegation token
const pkBytes = await crypto.subtle.exportKey("raw", kp.publicKey);
```

The WebAuthn key (YubiKey, Touch ID, etc.) signs a stroopwafel
delegation token binding the ephemeral pk. The browser then uses
the ephemeral sk to sign every RPC message — no user interaction
needed after the initial touch.

When the tab closes, the ephemeral sk is gone. The delegation
token expires. No cleanup, no revocation, no ceremony.

---

## The Same Code Path Everywhere

```
Testing:     STROOPWAFEL_IDENTITY=~/dev/test/agent-trader
Production:  STROOPWAFEL_IDENTITY=/home/agent-trader
Browser:     ephemeral keypair + WebAuthn delegation

             │
             ▼
     stroopwafel.ssh/load-keypair  (file-based identities)
     Web Crypto API                (browser identities)
             │
             ▼
     stroopwafel token + signed envelope
             │
             ▼
     PEP → Datalog → authorized / denied
```

The authorization model doesn't change. The Datalog facts don't
change. The token format doesn't change. Only the key storage
location changes — and that's a deployment choice, not an
architecture change.

---

## Every Trust Boundary: Evaluate Then Act

Every node in the delegation chain does the same two things:

1. **Evaluate** — am I permitted to do what's being asked? (`sw/evaluate`)
2. **Act** — issue a token (`sw/issue`) or serve the request (handler)

```
Root Authority          Intermediate Issuer       Resource Proxy
══════════════          ══════════════════        ══════════════

PDP: "may I             PDP: "may I               PDP: "may this
 delegate to             issue this                request access
 this issuer?"           to this agent?"           this resource?"
      │                       │                         │
      ▼                       ▼                         ▼
sw/issue                 sw/issue                  sw/evaluate
 → delegation token       → capability token        → allow/deny
```

The PDP is the same embedded engine everywhere — 594 lines, same
code, different policy facts at each node. Any process with a
signing key and a policy can issue tokens: a proxy could issue
session tokens, an agent could sub-delegate to a tool, a browser
could delegate to an ephemeral key.

### Context narrows at every step

Each node knows less about the world than its parent. The root
authority knows the full organizational policy — who exists, what
roles they have, what resources exist. The intermediate issuer
knows only its delegated slice. The proxy knows only the token
facts presented to it plus its own trust roots. The resource
handler knows the least — just "is this specific request permitted?"

The token carries just enough for the next boundary to decide,
nothing more. The proxy doesn't need to know the org chart. The
resource doesn't need to know the delegation chain. They just
evaluate the facts in front of them.

This is attenuation as information loss — each delegation step
forgets what it doesn't need to pass on. The security property
and the simplicity property are the same thing.

### Temporal attenuation: lifetime narrows with scope

```
Root policy:        valid 1 year     "ops-team may restart services"
Delegation token:   valid 1 week     "alice (ops-team) may restart /api/*"
Session capability: valid 30 min     "alice may restart /api/service"
Request envelope:   valid 2 min      "this specific restart request, now"
```

Each step folds the expected processing time over the capability.
The root doesn't know when alice will work. The issuer knows her
shift. The session knows she's logged in. The request knows it
should complete in seconds.

Because `not-after` can only narrow (attenuation guarantee),
nobody in the chain can extend what was granted above them.
Alice's session can't outlive her delegation. Her request can't
outlive her session.

This is also the operational safety net. A compromised session
token that expires in 30 minutes limits the blast radius in time,
not just in scope. You don't need to detect and revoke — you just
wait. The tighter the lifetime at the leaf, the less damage a
compromise can do.

---

## Summary

| Environment | Identity = | sk location | Bootstrap |
|---|---|---|---|
| Testing | Directory path | `{dir}/.ssh/id_ed25519` | `ssh-keygen` |
| Production | OS account | `~/.ssh/id_ed25519` | `ssh-keygen` (already done) |
| Browser | WebAuthn + ephemeral | Hardware + JS memory | `crypto.subtle.generateKey` |

No custom key formats. No key management tools to learn. No
ceremony beyond `ssh-keygen` and one YubiKey touch. The
infrastructure that already exists IS the identity infrastructure.

---

*Document status: design reference.*
*Last updated: April 2026.*
*Related: `docs/datalog-as-authorization-join.md`,
`docs/websocket-rpc-enforcement.md`,
`docs/dual-pep-client-server-enforcement.md` (in alpaca-clj)*
