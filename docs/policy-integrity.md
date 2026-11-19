# Policy integrity

Status: **design, nothing built.** Tracks issue #24. This page designs how the broker refuses a
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
whose `secretSlug` is that secret, in vault order:

```
tiresias/v2/policy-binding
service <slug> <upstream>
grant <index> <name> methods=<sorted> allow=<patterns> deny=<patterns> maxBody=<n|-> elevation=<0|1> logins=<0|1>
...
```

The grant's index within its service is included because ceilings are positional (least to most
privileged). A secret no grant uses binds to the empty list, so it can't be used until a policy is
approved for it.

`SecretEnvelope` v2 adds `SHA-256(binding)` to the value AAD next to the slug and version.
Rebinding keeps the DEK: it re-encrypts the value and re-wraps the DEK for the new version, so the
broker's leased DEK still opens it and no new lease seal is needed.

### Who rebinds

`VaultEditor` gains one entry point, `Approve(PolicyChange, HelloKeyWrapper fresh)`, used by the
Services window, the SQL Server and RavenDB setups, and `tir service add` (through the agent, which
shows the dialog). It unwraps each affected secret's DEK with a **newly created** `HelloKeyWrapper`
(one prompt), re-encrypts the value with the new binding, bumps the secret's version and saves.
The pure part, which secrets a change touches and what the dialog lists, is a planner tested
directly (`PolicyChangePlanner`).

Hand-editing `services` in `vault.json` stops being a supported way to change policy: the broker
README's setup step 5 becomes `tir service add`/`edit`.

### The broker

- `GrantSelector` is unchanged. Before a chosen grant's secret is opened, the broker computes the
  binding from its **current** vault and opens with it. A mismatch is audited as
  `policy-not-approved` and refused with 403. No secret reaches the upstream.
- `ReplaceVault` checks every leased DEK against the new vault's bindings. If any no longer opens,
  the reload is refused, the old vault kept, and the agent told (tray error, activity entry). Today
  that case silently drops the DEK.
- A minted placeholder and an elevation record `SHA-256` of the bindings of the service's grants
  at mint time. A request whose service hash differs is refused `policy-changed`; the consumer asks
  again and the user sees the new policy in the consent dialog.

### Rollback

Restoring an older `vault.json` restores an older, once-approved policy, which still opens. The
broker keeps the highest version it has seen per secret for the lease and refuses lower ones, so a
rollback mid-lease fails. Across restarts that needs storage the user's account can't write: the
Windows service's own profile. Until the service exists, a rollback to a previously approved
policy before unlock is an honest limit, written as such.

### Migration

Vault file `version: 2`. On the first unlock after the upgrade the app shows the services as they
are now ("Tiresias will now refuse changes to these settings unless you approve them"), and one
Hello prompt rebinds every secret. Until then the broker refuses v1 secrets with
`policy-not-approved`, and `tir doctor` names the step. A hosted broker gets its vault from the
admin's machine as today, after `tir vault migrate` there.

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

1. Binding, envelope v2, broker fail-closed on open and on reload, placeholder policy hash.
2. Approval dialog and `VaultEditor.Approve`, wired into the Services window, both setups and
   `tir service add`.
3. Migration on unlock, `tir vault migrate`, doctor line, broker README and CHANGELOG.
4. Rollback high-water mark, persisted once the Windows service exists.
