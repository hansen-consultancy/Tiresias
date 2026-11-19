# Policy integrity

Status: **phases 1 to 3 built** (binding, broker checks, approval, migration); the rollback
high-water mark waits for the Windows service (see *Phases*). Tracks issue #24. This page designs how the broker refuses a
service policy the user didn't approve: upstreams, grant rules and which secret each grant uses.

## The problem

A vault holds two things: sealed secrets and the `services` that say where and how each secret
may be used. The secrets are sealed under Windows Hello; the services are plain JSON, signed by
nobody, in a file the user's account can write. The solo broker reloads that file whenever its
timestamp moves (`SoloBroker.ReloadIfChanged`), and a hosted broker loads whatever `vault.json`
it is given at start.

So a program running as you, an AI agent included, can do this without a prompt:

1. Edit `vault.json`: set the `llm` service's upstream to `https://attacker.example.com`, or
   widen a read grant's allow list, or point a read grant at the admin key's secret.
2. Use any placeholder it already has, or one the user gives it for something else.
3. The broker sends the real credential to wherever the policy now says.

That defeats *use without seeing*, the promise the README makes against exactly these programs.
Reading the agent's memory also defeats it while the solo broker runs inside the app (documented
in desktop-app.md), but that takes malware; editing a JSON file in the user's profile is something
an agent with file access will do when a prompt injection asks.

## Decisions

- **The policy a secret may be used under is part of that secret's ciphertext.** No new key, no
  new signature, no new trust-chain link. Changing the policy means re-sealing the secret, and
  re-sealing needs its DEK, which only a Hello gesture (or the recovery key) opens.
- **A policy change is approved in the app, with a fresh Hello prompt**, after a dialog that shows
  what changes (old and new upstream, methods, paths, grant order, flags). `tir service add` and
  the Services window both end there. No pipe or CLI path rebinds without it, including while
  unlocked: the held wrapper opens user secrets, not policy changes.
- **The broker fails closed.** A secret whose ciphertext doesn't open under the current policy is
  not used; a reload that breaks a leased secret's binding is refused and the previous vault kept.
- **Placeholders and elevations carry the policy they were approved under.** A service whose
  binding changed stops honouring them.

## Design twice

| | **A. Hello-signed policy** | **B. Policy bound into each secret (chosen)** |
|---|---|---|
| What proves approval | An RSA signature by the Hello key over the canonical `services` | The secret's AEAD opening with the policy as associated data |
| New keys or formats | Hello public key in the vault and, for a hosted broker, in the trust chain (chain format bump) | Vault and envelope version bump only |
| Depends on #23 | **Yes.** Trust-chain links are signed with the DPAPI device key, so a program running as you could add its own "Hello" key. A is only as strong as the chain | No. Rebinding needs a DEK, not a chain link |
| Granularity | Whole policy; any edit re-signs everything | Per secret; editing one service touches only its secrets |
| Hosted broker | Must learn and pin the Hello key | Unchanged: it already decrypts with leased DEKs |
| Cost | One more crypto path to verify, key rotation story | Every policy edit re-seals the secrets it touches |

B wins on the point that matters: it adds no root of trust and doesn't wait for step-up (#23).

## Shape

### The binding

For each secret, `PolicyBinding.For(vault, slug)` returns canonical bytes, built from every grant
whose `secretSlug` is that secret, in vault order. It is compact JSON, so a pattern holding a space
or a newline can't be read two ways:

```json
["tiresias/v1/policy-binding",
 ["<service>","<upstream>",<index>,"<grant>","<secret>",["<methods, sorted>"],["<allow>"],["<deny>"],<maxBody|null>,<elevation>,<logins>]]
```

The grant's index within its service is included because ceilings are positional (least to most
privileged). A secret no grant uses binds to the empty list, so it can't be used until a policy is
approved for it.

A bound secret stores `SHA-256(binding)` of the policy approved for it (`policyHash` in vault file
version 2) and adds it to the value AAD next to the slug and version, so changing or clearing it on
disk makes the value fail to open. The broker uses a bound secret only while that hash equals the
binding of its current vault (`PolicyBinding.Allows`). Storing the hash, rather than recomputing
it, means whoever holds the DEK can always open the value and approve the policy now on disk after
seeing it; without it, an unapproved edit would lose the value for good. A vault with no bound
secret is still written as version 1.
Rebinding keeps the DEK: it re-encrypts the value and re-wraps the DEK for the new version, so the
broker's leased DEK still opens it and no new lease seal is needed.

### Who rebinds

Services change only through `VaultEditor.Plan(set, remove)` and `VaultEditor.Approve(PolicyChange,
HelloKeyWrapper fresh)`, used by the Services window (save and remove), the SQL Server and RavenDB
setups (which seal their secrets, then hand the service back to be approved) and `tir service
add`/`remove`. `Approve` re-plans from the file and refuses if the vault changed since the user
looked, then unwraps each affected secret's DEK with a **newly opened** `HelloKeyWrapper` (one
prompt), re-encrypts the value with the new binding (`SecretEnvelope.Rebind`), bumps the
secret's version and saves.

`PolicyChangePlanner`, pure and tested directly, decides what the user sees and which secrets
are rebound: those whose binding the change alters, and those of the services saved that aren't
approved for their policy yet. Saving a service unchanged therefore approves it as it is on disk,
which is how a user takes back a secret after an edit they didn't make, having seen it. Unbound
secrets the change doesn't touch stay unbound until migration. The dialog lists each service's
upstream and numbered grants (ceilings are positional) with secret slugs, methods, patterns and
flags; never a value.

`tir service add`/`remove` print the change and ask for approval in the app's dialog when the app
runs, in the terminal otherwise (as every `tir` consent does), then show the Hello prompt
themselves.

A new value (`VaultEditor.SealSecret`, e.g. `tir vault add`) approves no policy: it keeps the hash
approved for the previous version, and a new secret gets the empty binding, so a service using it
needs approval. Sealing over a bound secret whose policy changed without approval is refused.

Hand-editing `services` in `vault.json` stops being a supported way to change policy: the broker
README's setup step 5 becomes `tir service add`/`edit`.

### The broker

- `GrantSelector` is unchanged. Before a chosen grant's secret is opened, the broker computes the
  binding from its **current** vault and opens with it. A mismatch is audited as
  `policy-not-approved` and refused with 403. No secret reaches the upstream.
- `ReplaceVault` checks every leased DEK against the new vault's bindings. A bound secret whose
  ciphertext is unchanged but no longer opens means an unapproved policy change: the reload is
  refused, the old vault kept, and the solo broker logs it. A re-sealed secret (approved) loses its
  old DEK as before, and the agent seals the new one to the lease before the request goes on.
  Rotating a value mid-lease (`tir vault add`) is such a re-seal: a new ciphertext under a fresh
  DEK, sealed for the current policy, so it keeps working as today.
- Placeholders and elevations retire when their service's policy changes: the reload compares each
  service's hash (`PolicyBinding.ServiceHash`) and revokes the placeholders (audited
  `PlaceholderRevoked`, reason `policy-changed`) and elevations of every service that differs or
  is gone. The vault only changes there, so nothing needs storing at mint. The consumer asks again
  and the user sees the new policy in the consent dialog.

### Rollback

Restoring an older `vault.json` restores an older, once-approved policy, which still opens. The
broker keeps the highest version it has seen per secret for the lease and refuses lower ones, so a
rollback mid-lease fails. Across restarts that needs storage the user's account can't write: the
Windows service's own profile. Until the service exists, a rollback to a previously approved
policy before unlock is an honest limit, written as such.

### Migration

Vault file `version: 2`. After each unlock in the app that finds unbound secrets, the app shows
the services as they are now ("Tiresias will now refuse changes to these settings unless you
approve them"), and one Hello prompt rebinds every secret (`PolicyChangePlanner.Migrate`: each
service using one shown as it is; a secret no service uses is bound to the empty policy). `tir
vault migrate` does the same from a terminal. Until then the broker refuses unbound secrets with
403 `policy-not-approved` but keeps their leased DEKs, so they serve as soon as migration binds
them (same DEK), and `tir doctor` fails the vault check, naming the step. A hosted broker gets its
vault from the admin's machine as today, after `tir vault migrate` there.

## Tests

- `PolicyBindingTests`: canonical form pinned; any change to upstream, method, pattern, order,
  flag or `secretSlug` changes the bytes; unrelated services don't.
- `SecretEnvelopeTests`: a v2 secret opens only under its binding.
- `BrokerStateTests`: tampered upstream, widened allow, swapped secret, reordered grants each give
  403 `policy-not-approved` and no upstream call; a breaking reload is refused; a placeholder minted
  before an approved change gets `policy-changed`; a lower version mid-lease is refused.
- `PolicyChangePlannerTests`: which secrets a change touches; the dialog lines show keys and
  policy, never values.
- Migration: a v1 vault is refused until approved, then served.

## Not in scope

- Step-up at the broker for minting and elevation (#23). B doesn't need it; it would strengthen the
  approval dialog's Hello prompt into something the broker checks itself.
- Protecting the unlocked agent's memory. That is the Windows service's job (desktop-app.md).

## Phases

1. **Built.** Binding, bound envelope, broker fail-closed on open and on reload, placeholders and
   elevations retired on a policy change.
2. **Built.** Approval dialog and `VaultEditor.Approve`, wired into the Services window, both
   setups and `tir service add`/`remove`; the approved hash stored with each bound secret.
3. **Built.** Migration on unlock, `tir vault migrate`, doctor line; the broker refuses unbound
   secrets.
4. Rollback high-water mark, persisted once the Windows service exists.
