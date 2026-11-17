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
2. Choose a mode (see the open question below).
3. Enrol this device: pin the broker key, scan or paste the genesis hash.
4. Optional: scan the machine for plaintext secrets (the `doctor` checks) and offer to import
   them.

## Open questions

1. **Solo mode, no separate broker host.** Most individual developers don't run a VPS. A solo mode
   could run the broker inside the app on the same machine. It keeps encryption at rest,
   placeholders, consent and audit. It loses the fixed egress IP and the separation between the
   machine holding secrets and the machine running agents. It would make the first ten minutes
   trivial. The trade-off has to be stated plainly in the UI.
2. **Broker install for teams:** a container image, a single-file binary plus a systemd/Windows
   service, or both. The app could generate the broker's config and the enrolment bundle.
3. **Notifications:** Windows toast for loud events (new device, break-glass) in addition to the
   control plane's push.
