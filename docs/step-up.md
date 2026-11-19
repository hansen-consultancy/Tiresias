# Step-up at the broker

Status: **design, not built**. Tracks issue #23. This page designs how the broker refuses to mint a
placeholder, switch on an elevation or issue a token unless the user approved that exact operation.

## The problem

Every management call to the broker carries a device signature (`RequestSignature`), and that is
all the broker checks. The device key is DPAPI-protected to the user's account, with no user
presence. `tir grant`, `tir elevate` and `tir exec` show a Hello prompt first
(`HelloKeyWrapper.ConfirmPresence`), but the prompt only gates the client: the broker cannot tell a
request `tir` sent after a prompt from one sent by any other program.

So while you're unlocked, a program running as you, an AI agent included, can do this without a
prompt. It loads `Tiresias.Agent.dll` from the app folder, or reads `device.key` with DPAPI and signs
requests itself:

1. `POST /placeholder` for any service, with no ceiling (every grant) and a 10-hour duration.
2. `POST /elevate` for that service's write grant, for as long as the lease lasts.
3. `POST /token/{service}` for a GitHub App service, which returns a working installation token,
   valid for up to an hour, to the caller.

The broker README lists this under Honest limits ("Step-up is local only"). Policy integrity (#24)
closed the other route around consent, editing `vault.json`, so this is now the easiest one. The
token route also hands the caller a usable credential, not a placeholder.

## Decisions

- **The broker checks approvals itself.** `/placeholder`, `/elevate` and `/token` need an
  **approval** as well as the device signature: the operation's exact parameters, signed with a
  key only an unlocked agent or a fresh Hello prompt can produce.
- **The approval key comes from the vault, not from the device.** It is derived from the Hello wrap
  key and the lease id. The broker learns its public half only in the same `/lease/seal` that
  delivers DEKs which really open the vault's secrets. A program that holds the device key, but
  can't open the vault, can't register a key of its own.
- **An approval is the request.** The broker takes service, grant or ceiling, duration, consumer
  and purpose from the signed approval, never from fields beside it. Nothing approved can be
  widened in transit.
- **Every prompt stays where it is.** `tir grant`, `elevate` and `exec` keep their one Hello prompt,
  which now derives the key. The app's consent dialogs (terminal environment, `tir run`, user-secrets
  references) sign with the wrap key it already holds while unlocked. No new prompt anywhere.

## Design twice

| | **A. Hello signature per operation** | **B. Lease approval key from the wrap key (chosen)** |
|---|---|---|
| What the broker verifies | An RSA signature by the Hello key over each operation | An Ed25519 signature by the lease's approval key over each operation |
| How the broker learns the key | The Hello public key is registered in the trust chain or `Broker:Devices`. Links and requests are signed with the DPAPI device key, so **a program running as you can register its own**. It needs a paper-key-signed link to be sound | Inside `/lease/seal`, accepted only together with DEKs that open the vault. The vault is the anchor, as in #24 |
| Prompts | One Hello prompt per operation, **including every app consent**: a prompt per terminal, per `tir run`, and per app start with user-secrets references | Unchanged: one for `tir grant`/`elevate`/`exec`, none extra in the app |
| Against malware that reads the app's memory | Holds | Fails, but that malware already reads the wrap key and every value (desktop-app.md). A adds nothing there |
| New formats | Trust-chain body, RSA verification in the broker | Approval record, one field in the seal request |

B wins: it adds no root of trust and no prompts. Against the one attacker A would also stop, B
already loses everything else.

## Shape

### The approval key

`ApprovalKey.Derive(wrapKey, leaseId)`: HKDF-SHA-256 of the Hello wrap key with info
`tiresias/v1/approval\n{leaseId}`, used as an Ed25519 seed. The Hello signature behind the wrap key
is deterministic (the wrap already depends on that), so a later prompt derives the same key for the
same lease. A new lease gives a new key, so an approval key can't outlive its lease.

`/lease/seal` gains `approvalKey`, the raw public key. Each DEK is sealed to the lease key with that
key in its context (`lease\n{leaseId}\n{slug}\n{approvalKey}`), so sealed DEKs copied from your seal
can't carry another key. The broker accepts the key only when:

- the seal accepts at least one DEK under that context, and
- the lease has no approval key yet, or this is the same one.

A later seal into the open lease (`SealIntoOpenLeaseAsync`) sends the same key. A program that holds
only the device key can begin its own lease, but it can't seal anything into it, so that lease has
no approval key and nothing it can approve. Its `/lease/begin` still ends your lease: that is denial
of service, not access (see *Not in scope*).

### The approval

```json
["tiresias/v1/approval","<op>","<leaseId>","<service>","<grant|ceiling|null>",<seconds>,"<consumer>","<purpose>","<observed|null>",<issuedAt>,"<nonce>"]
```

`op` is `mint`, `elevate` or `token`. The request body is that JSON and a signature. The broker:

1. Refuses with 401 when there is no approval, the signature doesn't verify under the **current**
   lease's approval key, `op` doesn't match the route, `issuedAt` is outside `RequestSignature`'s
   window, or the nonce was seen before (`ReplayGuard`).
2. Builds the `AccessRequest`, the elevation or the token request from the approval alone, then
   goes on as today (`Consent.Validate`, `GrantSelector`, policy binding).
3. Audits the approval's consumer, purpose and observed process, as `Mint` does now. Refusals are
   audited `approval-required` or `approval-invalid`.

Elevation keeps its lease cap and is now bound to the approved minutes. A token approval names its
service. Revoking a placeholder and ending a lease stay device-signed only: each only takes access
away.

### Who signs

| Flow | Who asks the user | Who signs |
|---|---|---|
| `tir grant`, `tir elevate`, `tir exec`, app not running | `tir`, in the terminal | `tir`: its Hello prompt (in place of `ConfirmPresence`) opens the wrapper and derives the key |
| `tir grant`, `tir exec`, app running | The app's consent dialog (`ControlRequest.Consent`) | The app: the reply carries the signed approvals, and `tir` posts them |
| Terminal environment, `tir run`, NuGet, user-secrets references | The app's dialogs, or a consent the user saved there | The app, with the wrap key it holds while unlocked (`AgentKeys`) |

A consent the user saved in the app (for example "allow this program") still approves without a new
dialog. That is the user's standing decision, made in the app. The broker now knows the app made it.

## Tests

- `ApprovalTests`: canonical form pinned; changing any field breaks the signature; the same Hello
  wrap key and lease always derive the same key, and another lease a different one.
- `BrokerStateTests`:
  - a mint, elevation or token without an approval gets 401 and nothing is minted;
  - an approval for another lease, op, service, grant or duration is refused;
  - a replayed or stale approval is refused;
  - an approval key from a seal with no valid DEK is ignored, and a second, different key is refused;
  - a valid approval mints exactly what it names.
- Endpoint tests: `/token` with a device signature but no approval calls nothing upstream.
- App logic: a consent reply carries one approval per request, built from the lines the user saw.

## Not in scope

- **Denial of service with the device key.** A program running as you can still begin a lease
  (ending yours), end it, or revoke placeholders. Each takes access away, never gives it.
- **Trust-chain links.** They are signed with the same DPAPI device key, so a program running as
  you on an admin's device can sign an `AddDevice`. That is the same flaw on another route and
  needs its own issue: links that add a key should need the paper key, or a Hello-derived
  signature like this one.
- **Reading the app's memory.** The wrap key, and so the approval key, are in the unlocked agent's
  memory. That is the Windows service's job (desktop-app.md).
- **Driving the app's consent dialog with synthetic input.** A program at the same integrity level
  can click Allow. Hello prompts can't be driven that way; app dialogs can.

## Phases

1. Core: `ApprovalKey`, the approval record, signing and verifying, all pure. Broker: register the
   approval key at seal and verify approvals when they are present.
2. Clients sign: `tir grant`/`elevate`/`exec`, the app's consent reply, and the app's own mints.
3. The broker refuses `/placeholder`, `/elevate` and `/token` without an approval. Older `tir`
   builds get 401 `approval-required` and must update. The Honest limits line in the broker README
   is replaced, and the change gets a CHANGELOG line.
