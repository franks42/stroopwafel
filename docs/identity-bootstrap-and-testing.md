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
*Last updated: March 2026.*
*Related: `docs/datalog-as-authorization-join.md`,
`docs/websocket-rpc-enforcement.md`,
`docs/dual-pep-client-server-enforcement.md` (in alpaca-clj)*
