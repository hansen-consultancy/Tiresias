# The solo broker as a Windows service

Status: **built, not yet tried on a real install**. This page designs how solo mode's broker
leaves the app's process ([desktop-app.md](desktop-app.md), *Solo mode*), and what moves with it.

## The problem

In solo mode the broker runs inside the app (or `tir agent`), as the user. Any program running as
the user can read that process's memory: the leased DEKs, the lease key, and with them every
leased secret. It can also rewrite the files the broker trusts (the trust chain and its accepted
head, the audit log), and restore an older `vault.json` while the app is locked, which brings back
an older, once-approved policy ([policy-integrity.md](policy-integrity.md), *Rollback*).

A process under another account is out of reach: without admin rights, a user's programs can't
open it or write the files only it can write.

## Decisions

- **The broker runs as the `Tiresias` service under its virtual account `NT SERVICE\Tiresias`**,
  on `127.0.0.1:7780` as today, so nothing that calls the broker changes.
- **Its binary lives where only admins write.** `tir solo service install` copies the folder of
  the `tir` it runs from to `%ProgramFiles%\Tiresias\Broker` and registers that copy
  (`tir.exe solo service run`). A service run from the user's own folder would run whatever the
  user's programs put there, under the service's account.
- **Its state lives where only it and admins write**: `%ProgramData%\Tiresias\Broker`, readable and
  writable by SYSTEM, Administrators and the service only. It holds the broker identity, the trust
  chain and its accepted head, the audit log, the rollback high-water marks, and `service.json`
  (vault path, pinned genesis hash, time zone), written at install.
  Install makes it, and `%ProgramData%\Tiresias`, owned by Administrators, as the admin tier
  does: a folder a user made there first is moved aside, since its owner could change its ACL
  back. The binaries are copied the same link-safe way.
- **The vault stays in the user's profile.** Install grants the service read access to its folder.
  Writing it is still the user's: policy changes are bound into the ciphertext and need Hello, and
  a restored older vault is refused against the marks the service keeps.
- **The rollback mark persists.** The service keeps, per secret, the highest version it has
  loaded, and refuses a vault below it whether a lease is open or not. A secret below its mark at
  start is left out, and audited, until a newer one is saved.
- **The trust chain moves.** Install verifies the user's solo chain against the genesis pinned in
  the Keyring and copies it into the service's folder. From then on the service's copy is the
  chain; `tir trust bind-hello` extends it with `POST /trust/chain` as with any broker.
- **The Keyring re-pins.** The service has an identity of its own (the app's is DPAPI-bound to the
  user), so install re-pins the solo tenant to it, and uninstall back to the app's.
- **The app hosts the broker only when the service isn't installed.** With the service, the agent
  watches the vault and seals new or re-sealed secrets to the open lease over HTTP, which the
  in-app broker did through a callback.
- **Admin once.** Install and uninstall need an elevated `tir`. Nothing else does.

## Design twice

| | **A. Service under its own account (chosen)** | **B. Same process, hardened** |
|---|---|---|
| Memory | Out of reach of the user's programs | Readable by any program running as the user |
| Files it trusts | Only it and admins write them | The user's profile |
| Install | Admin once | None |
| Rollback while locked | Refused, marks persist | Honest limit |

B can't be hardened: a process can't keep its memory from another process of the same user.

## Shape

- `tir solo service install` (elevated): checks solo mode is set up, copies the binaries, creates
  the state folder with its ACL, copies and verifies the chain, writes `service.json`, grants read
  on the vault folder, creates and starts the service (`sc.exe`, start `auto`), and re-pins the
  Keyring to the identity the service creates on first start, which it writes as `identity.pub`
  in its state folder.
- `tir solo service run`: what the service manager starts. Reads `service.json`, hosts
  `BrokerHost` with `UseWindowsService`, reloads the vault when it changes (as the app does) and
  persists the marks (`Broker:HighWaterPath`).
- `tir solo service uninstall` (elevated): stops and deletes the service, removes the binaries,
  re-pins the Keyring to the app's identity, and leaves the state folder (the audit log) in place.
- `tir doctor` and the status page: "broker process" is Ok when the service runs, a failure when
  it is installed but stopped, and the warning to install it otherwise.

## Honest limits

- **Admins still win.** An admin, or malware that gets admin, can read the service's memory.
- **The process line may be thinner.** Under its own account the service may not read the image
  path of the user's processes; then the consent dialog and audit show the PID only.
- **The app and `tir` still hold the approval key while unlocked**, as before ([step-up.md](step-up.md)).

## Tests

- `BrokerStateTests`: persisted marks survive a new `BrokerState`; a vault below them is refused
  without a lease; a secret below its mark at start is left out and audited.
- `DoctorTests`: the three "broker process" lines.
- `BrokerServiceLayoutTests`: paths, the `service.json` round trip, and the `sc.exe` arguments
  (binary path quoted, virtual account).
