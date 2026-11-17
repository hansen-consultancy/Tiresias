# Desktop app (design draft)

**Status:** draft for discussion, not built yet.

Tiresias has to be easy to install and use. A security tool that needs a terminal for daily use
gets bypassed. So the everyday experience is a **tray app**. The `tir` CLI stays, for scripting,
CI and people who prefer it, and it talks to the same agent.

## Why the GUI is not optional

Several flows are UI by nature. A CLI can only fake them:

- **Consent prompts** come from *other* processes: an app loading user secrets, or an agent
  asking for a placeholder. Nobody is watching a terminal at that moment.
- **Lease state** (unlocked / locked / expiring) needs to be visible at a glance.
- **Editing secrets** needs a window that stays out of screenshots and screen shares
  (`WDA_EXCLUDEFROMCAPTURE`), with values masked by default.
- **The activity view** (who accessed what, recently) is a list to scroll and filter.

## One process: the tray app *is* the agent

Today `tir agent` is a long-running terminal process: heartbeat, and ending the lease on
lock or sleep. The tray app takes over that role. There is one agent per user session, and it
hosts:

| Concern | Today | In the app |
|---|---|---|
| Lease heartbeat, end on lock/sleep | `tir agent` | background service |
| User-secrets pipe server and consent | not built | consent dialog: executable, keys only |
| Placeholder consent (`tir grant`, `tir exec`) | terminal y/N | dialog; the CLI asks the agent |
| Unlock / lock | `tir unlock`, `tir lock` | tray menu, plus the Hello prompt |
| Secrets editing | `tir vault add` | capture-excluded editor: the full JSON view, like App Service |
| Activity | not built | window with filters (tenant, service, process, decision) |
| Health | `tir doctor` | status page, same checks, a "fix" button where it's safe |
| Enrolment | `tir enroll` + flags | first-run wizard |

The CLI becomes a thin client of the agent over the same named pipe, so the two never disagree
about state. Without the app running, the CLI keeps working standalone, exactly as today.

## Technology

- **WPF on .NET 11 (`net11.0-windows`)**, the same target the Keyring already has for Windows
  Hello and the TPM. The Keyring's logic moves into a library both the CLI and the app reference.
  WinUI 3 was considered and rejected: heavier deployment and a smaller ecosystem for a
  tray-first app. Avalonia is the route if macOS or Linux desktops ever matter.
- Tray icon via `H.NotifyIcon` / `Hardcodet.NotifyIcon.Wpf`. MVVM via CommunityToolkit.Mvvm.

## Install and update

The goal is one command or one download, then a first-run wizard:

- **winget:** `winget install Tiresias`. The app and `tir` are installed together, and `tir` is
  put on the PATH.
- **Velopack** for the installer and silent auto-update. MSIX is the alternative, but it
  complicates the named pipe, the startup task and CLI-on-PATH.
- **Code signing:** Azure Trusted Signing. An unsigned security tool is a non-starter
  (SmartScreen).
- **NuGet packages** stay the way to *consume* protected user secrets. The app is not needed to
  build, only to unlock.

## First-run wizard

1. Create the recovery key: show it once, ask the user to confirm two words from it, then print
   or save it.
2. Choose a mode: **solo** (the default, nothing else to set up) or **with a broker** (see
   [Solo mode](#solo-mode)).
3. Enrol this device: pin the broker key, scan or paste the genesis hash.
4. Optional: scan the machine for plaintext secrets (the `doctor` checks) and offer to import
   them.

## Solo mode

Most individual developers don't run a VPS. They still deserve encryption at rest, placeholders,
consent and audit. Solo mode runs the broker on the workstation itself, so the first ten minutes
need nothing but the app.

### What runs where

- The **broker** is the same code as the hosted one, run as a **Windows service under its own
  virtual account** (`NT SERVICE\Tiresias`) and listening on loopback only. Its own account matters:
  processes running as the user cannot read a service's memory without admin rights, so an agent
  running as you cannot lift the leased keys out of it. Installing the service needs admin once;
  without it the broker runs inside the tray app, and the app says so (see below).
- The broker identifies the calling process from the loopback connection itself, so the
  **forwarder** is not needed.
- The **trust chain** has one device and a genesis created on this machine. The paper recovery key
  exists as in every mode; genesis is co-signed by an Ed25519 key derived from it (HKDF, label
  `tiresias/v1/paper-signing-key`), so one sheet of paper serves both.
- **Built so far:** `tir solo init`, the broker hosted inside the agent on `127.0.0.1:7780`, and
  the doctor lines below. **Not built yet:** the Windows service; the broker always runs inside the
  agent, and it restarts at unlock when the vault changed (a new secret), which ends open
  placeholders.
- The **control plane** is optional, exactly as with a hosted broker.

### What it keeps and what it gives up

| | Solo | With a broker |
|---|---|---|
| Encryption at rest, Hello unlock, leases | yes | yes |
| Placeholders, grants, consent, audit, anchoring | yes | yes |
| Agents never see a secret value | yes | yes |
| Fixed egress IP that upstreams can allow-list | **no**, requests leave from your own connection | yes |
| Secrets held on a different machine from the agents | **no** | yes |
| Protected from code running as admin on the workstation | **no** | yes, outside the lease's reach |
| Works offline | yes | no |

Solo mode protects against what reads files, environment variables and prompts: an agent, a
malicious package, a leaked transcript. It does not protect against an attacker who already has
admin on the machine. Neither does any tool that keeps the secrets on that machine.

### Saying it plainly

- The tray menu shows **Solo** next to the lease state. `tir doctor` and the status page list the
  two lines marked **no** above, and say which one applies if the broker fell back to running inside
  the app ("Broker runs inside the app: install the service for process isolation").
- The first-run wizard picks solo by default and states the trade-off in one sentence before
  continuing.

### Moving to a broker later

A **Move to a broker** wizard enrols the new broker host into the existing chain, re-seals the
vault to the broker's key and switches the local broker off. Placeholders, grants and the audit
history carry over; only the upstream allow-lists need the new egress IP.

## Open questions

1. **Broker install for teams:** a container image, a single-file binary plus a systemd/Windows
   service, or both. The app could generate the broker's config and the enrolment bundle.
2. **Notifications:** Windows toast for loud events (new device, break-glass) in addition to the
   control plane's push.
