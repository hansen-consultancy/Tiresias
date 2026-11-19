# Desktop app

**Status:** a first version is built (`src/Tiresias.App`, `Tiresias.exe`). This page is the design;
[What is built](#what-is-built) says how far it got. Hands-on steps: [testing-on-windows.md](testing-on-windows.md).

Tiresias has to be easy to install and use. A security tool that needs a terminal for daily use
gets bypassed. So the everyday experience is a **tray app**. The `tir` CLI stays, for scripting,
CI and people who prefer it, and it talks to the same agent.

## What is built

- **Tray icon** following the taskbar theme (light/dark icon). Its menu shows the state (not set
  up, locked, unlocked until 18:00, built-in broker not running), **Solo** when the broker runs in
  the app, Unlock (Windows Hello) / Lock, Edit user secrets, Activity, Status and Quit.
- **One per user session.** Starting it again brings the running one forward. `tir agent` refuses
  to start while the app runs.
- **The agent runs in the app:** the user-secrets pipe server, the lease heartbeat, locking on
  workstation lock, and in solo mode the broker on `127.0.0.1:7780`.
- **Consent dialog**, topmost. It shows the program asking (its path, selectable, with **Open
  folder** to look at it in Explorer) and the keys or what the placeholder gets, never values.
  For `tir run` it shows the whole command line under the heading. Answers are Allow once / Allow for this session / Deny. Deny has
  focus and is the Esc answer. A countdown runs, and no answer means Deny. Requests that arrive
  while one is open wait their turn, and the dialog shows how many are waiting. Workstation lock,
  logoff or sleep answers every open dialog with Deny.
- **"This wasn't me"**, beside Deny on every consent dialog, for a prompt you didn't cause (it
  could be malware). It denies the request and locks at once: session consents, terminal and NuGet
  allowances are forgotten, the terminals' placeholders revoked and the broker lease ended. Until
  you unlock with Windows Hello from the tray or the status page, every request is refused without
  a dialog; `tir unlock`, a terminal or NuGet can't unlock in the meantime. The asking program
  (for `tir` requests, the program that ran `tir`) is blocked by path and by the file's SHA-256,
  so a copy elsewhere is blocked too: it is refused without asking, also after unlocking, until you
  **Unblock** it on the status page. Lockdown and blocklist live in
  `%LOCALAPPDATA%\Tiresias\blocklist.json`; a damaged file counts as locked down. Activity records
  the incident with the process and the processes that started it. A follow-up window shows the
  program's folder (selectable, with **Open folder**), **End this process**, and how to scan with
  Microsoft Defender. Tiresias changes nothing else: no network or security setting, nothing that
  needs an administrator; that would cut off investigation without protecting the vault.
- **`tir` uses the app when it runs.** `tir grant` and `tir exec` ask in the app's dialog,
  `tir unlock` and `tir lock` go through it, and `tir status` prints its state. Without the app
  they work in the terminal as before.
- **Secrets editor**, excluded from screen capture (`WDA_EXCLUDEFROMCAPTURE`). Values are masked
  and shown one at a time. It drops every value when the agent locks, and saving always seals.
  A user-secrets folder is named after its id only, so the editor names it after the project that
  uses it: from folders the user adds under **Project folders** (rescanned each time it opens;
  only project files are read, never `bin`, `obj` or `node_modules`), from **Find a project**, and
  from the program that asked the agent for that id (traced back from its `bin` folder). The map
  lives in `%LOCALAPPDATA%\Tiresias\projects.json`, paths and ids only. Ids no scanned project
  uses are grouped under **No project found** and can be moved to the Recycle Bin, once at least
  one folder has been scanned.
- **Activity window** over the local logs: the agent's user-secrets decisions (`activity.jsonl`)
  and the solo broker's audit (`solo\audit.jsonl`). Filters: period, outcome, source and text.
- **Status page** running the same checks as `tir doctor`, with copy details.
- **First-run wizard.** It creates the Hello key, shows the recovery key once, asks two of its
  groups back, then asks for a mode: solo by default, a broker, or user secrets only. It is
  resumable: a closed wizard restarts at the first missing step. A solo setup resumed after the key
  was shown asks for the key to be typed back. If that key is lost and nothing is sealed to it yet,
  the wizard offers a new one. Where sealed secrets are already here and no recovery key is stored
  (files copied from another PC), it asks for the key they were sealed with instead of making a
  new one, so one paper keeps covering everything.
- **Restore with the recovery key.** The Windows Hello key can't be copied or backed up: a new PC,
  a reset TPM or a removed Hello credential gives a new one. Every sealed item also carries a copy
  of its key for the paper recovery key, so the status page notices items this Hello can't open and
  offers **Restore**: type the paper key and each item gets a copy for this Hello. Nothing is
  decrypted or re-encrypted, and the recovery copy stays. `tir recovery restore` does the same. A
  solo broker's device and identity keys are bound to the old PC's Windows account and are not
  restored: set solo mode up again there.
- **Errors** say what happened, why it matters and what to do next, with a button for that next
  step and "Copy details" (no stack trace; that goes to `%LOCALAPPDATA%\Tiresias\app.log`).
- **Wording:** every string is in `src/Tiresias.App/Strings.resx`, and a test keeps the file and
  the code in step. The exception is the doctor checks, whose text comes from `Tiresias.Core` so
  that `tir doctor` and the status page say the same thing.

**Not built yet:** the Windows service for the solo broker, and the "Move to a broker" wizard. The
wizard doesn't enrol you with a broker either: use `tir enroll`, which the wizard points to. Other
gaps: the full-JSON editor view, scanning the machine for plaintext secrets, and toasts. winget is
also not built: install from source.

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
| User-secrets pipe server and consent | not built | consent dialog: executable, keys, and what each `tiresias:` value asks for |
| Placeholder consent (`tir grant`, `tir exec`) | terminal y/N | dialog; the CLI asks the agent |
| Unlock / lock | `tir unlock`, `tir lock` | tray menu, plus the Hello prompt |
| Secrets editing | `tir vault add` | capture-excluded editor: the full JSON view, like App Service |
| Services for `tir exec` | `tir service add`, `list`, `remove` | Services window: list, add (same checks as the CLI), remove; each change shown and approved with Windows Hello |
| SQL Server per-lease logins | (none yet) | Services window, **Set up a SQL Server**: runs the setup script with a one-off administrator sign-in, seals the provisioner, saves the service |
| Activity | not built | window with filters (tenant, service, process, decision) |
| Health | `tir doctor` | status page, same checks, a "fix" button where it's safe |
| Enrolment | `tir enroll` + flags | first-run wizard |
| Restore after Hello is lost | `tir recovery restore` | status page notice, or the first run on a PC with copied secrets |

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

- **winget:** `winget install Tiresias` (not built yet). The app and `tir` are installed together,
  and `tir` is put on the PATH.
- **Velopack** for the installer and silent auto-update. MSIX is the alternative, but it
  complicates the named pipe, the startup task and CLI-on-PATH.
- **Code signing:** Azure Artifact Signing (formerly Trusted Signing). An unsigned security tool is
  a non-starter (SmartScreen). Setup and release steps: [releasing.md](releasing.md).
- **NuGet packages** stay the way to *consume* protected user secrets. The app is not needed to
  build, only to unlock.

### How updates work (built)

- **Where from:** this repository's GitHub Releases, from the `app-v*` tags that
  `.github/workflows/app-release.yml` publishes. They are separate from the NuGet `v*` releases.
  The installer is `TiresiasApp-win-Setup.exe` on each app release (`TiresiasApp-win-arm64-Setup.exe`
  for Windows on Arm, which then runs natively rather than emulated). It installs per user, with no
  admin rights, into `%LOCALAPPDATA%\TiresiasApp`, and `tir.exe` sits next to `Tiresias.exe`.
  Uninstalling deletes that folder only. The vault, Keyring and logs live in
  `%LOCALAPPDATA%\Tiresias` and stay, so a reinstall unlocks the same secrets. The app puts that folder on the user
  `PATH` at every start (so a moved install heals) and Velopack's uninstall hook takes it off.
  The installer also makes it start at sign-in (HKCU `Run`, `StartWithWindows.cs`), switchable on
  the status page and removed on uninstall, so apps that start at sign-in with sealed user secrets
  find the agent. Only an installed copy registers; a development build's folder goes stale.
- **Development builds:** a copy Velopack didn't install is a development build (`AppBuild`,
  `Logic/BuildInfo.cs`). Its tray icon gets an orange corner, its version and commit show in the
  tray, status page and About window, it never updates itself and it leaves PATH alone. Only one
  copy runs per session (a mutex); a second start of the same folder brings the first forward,
  and a different copy asks to switch: the running one quits over the control pipe (`quit`,
  refused while a consent, editor or setup window is open), then the new one takes the mutex.
  An app older than 0.1.0-preview.5 can't hand over and is quit from its tray menu.
- **When:** at start, then daily. A check that fails (no network, GitHub down) is logged and
  retried an hour later; the user sees nothing. A preview build follows preview releases, a stable
  build only stable ones.
- **Silently:** a new version downloads in the background (a delta when possible). The tray menu
  then offers "Update to X available - restart to apply".
- **Never in the way:** applying is always the user's click. It first shows the release notes,
  which are that version's section of `CHANGELOG.md`, the same text as the GitHub release. While
  a consent dialog, the secrets editor or the setup wizard is open, it says to finish that first.
- **Rollback-safe:** the app quits the normal way, ending the lease, and Velopack swaps the files
  after it has exited, then starts the new version. If applying fails, the version that was
  running stays installed. Settings and the vault live in `%LOCALAPPDATA%\Tiresias`, outside the
  install folder, so an update never touches them.
- **A build run from source** (`dotnet run`, `dotnet publish`) doesn't update itself, and says so
  in its log.

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
