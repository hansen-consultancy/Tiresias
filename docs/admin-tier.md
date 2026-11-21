# The admin tier: a privileged service, optional

Status: **step 1 built** (#91): the service, its pipe and `status`, install, update and remove,
the first-run and About offers, the doctor line and the action log ([Build order](#build-order)).
None of the features is built yet; the service answers `status` and refuses every other action.

Tiresias works for an ordinary user account and keeps doing so. A user who can approve one UAC
prompt can add a small Windows service that does what an ordinary account can't: hold the decoys
out of the user's reach, listen for them from boot, name every read of a decoy file, and stop a
program that used one. Declining it, or removing it, leaves Tiresias exactly as it was.

The service is the most valuable thing on the machine to attack: a bug in it is a privilege
escalation. So the design starts from what it must never do.

## Principles

1. **Never more than the caller already has, except to protect.** An ordinary caller can ask the
   service to watch, record or stop something of its own user's. Anything that *weakens* protection
   (thaw a program, lift a network block, hand the decoys back, remove the service) needs an
   **elevated** caller: a UAC prompt, which a program running as the user can't click.
2. **A fixed list of actions**, each with typed arguments. No paths to run, no command lines, no
   generic file or registry access.
3. **Only its own user's things.** Every action is keyed by the caller's user SID: its decoys, its
   processes, its events. One user can't see or act on another's.
4. **Nothing runs from a folder the user can write to.** The service's files live under
   `%ProgramFiles%`, its state under `%ProgramData%`, both closed to users.
5. **Every action recorded**, with the caller, never a value.

## Where it runs

| | |
|---|---|
| Service | `TiresiasAdmin`, display name "Tiresias admin tier", automatic start, restart on failure |
| Account | `LocalSystem`, with only `SeSecurityPrivilege` and `SeChangeNotifyPrivilege` kept (`sc privs`). A virtual account can't do any of the jobs: suspending a user's process, adding firewall filters, setting audit rules and reading the Security log all need SYSTEM or an administrator |
| Binary | `%ProgramFiles%\Tiresias\Admin\tiresias-admin.exe`, copied there by the install step from the app's own `admin\` folder (published self-contained into it). The app installs per user, in a folder the user can write to: a service started from there would run whatever replaced it as SYSTEM |
| State | `%ProgramData%\Tiresias\Admin\`, and `%ProgramData%\Tiresias` above it, inheritance off, owned by Administrators, SYSTEM and Administrators only: the decoy sets, the event queue, the action log. A user can create folders in `%ProgramData%`, so a folder already there under either name that isn't owned by SYSTEM or Administrators, or is a link, is moved aside (`….untrusted-<time>`) and made again, never used: its owner could change its ACL back. The service refuses to start while either folder isn't so |
| Pipe | `\\.\pipe\tiresias.admin`, see below |

The broker's own service (desktop-app.md, *What runs where*) is a different thing: it runs under a
virtual account precisely so that it holds no privilege. The two stay apart; this one is never the
broker.

### Install, update, remove

- **Install** (first run, or About): the app starts itself elevated, `Tiresias.exe --admin-tier
  install`, through UAC. That process copies the service's files to `%ProgramFiles%`, creates the
  state folder with its ACL, creates the service with its privileges and failure actions, and
  starts it. Running it again repairs or updates; it is idempotent.
- **Update**: Velopack updates the app per user and can't touch `%ProgramFiles%`. The service
  reports its version; when the app is newer, Home has a finding, **Update the admin tier**, which
  runs the same install step. The protocol is versioned, so an older service keeps working until
  then.
- **Remove** (About): `Tiresias.exe --admin-tier remove`, elevated. It asks the service to undo
  everything (thaw, lift filters, remove audit rules, restore the audit policy it changed, hand the
  decoys back to the user's agent), then stops and deletes the service and both folders.
  Uninstalling the app runs it too, when the service exists, behind its own UAC prompt; Velopack
  gives an uninstall hook only seconds, so the app waits 20 s for it and uninstalls anyway.
  Until `teardown` is built (step 2 onwards, as each feature lands) there is nothing to undo, and
  remove only stops and deletes.
- The elevated process reports back by exit code (`AdminSetupResult`): done, failed, files missing
  (a development build without the `admin\` folder), or set up but stopped again at once (the
  service found its state folder or pipe name not its own; the Windows event log says which).

## The pipe

`\\.\pipe\tiresias.admin`. The service creates it with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL
of SYSTEM full control, Authenticated Users read and write (not create), and NETWORK denied:
Authenticated Users includes callers over SMB, whose process ids mean nothing here. The next
instance is created before a connected one is served, so the name is never free for another
process to take.

**Both ends check the other.**

- The service names the caller from the pipe (`GetNamedPipeClientProcessId`, then the process's
  token): its user SID, session, whether the token is elevated, and its image path. Callers that
  are services (SYSTEM, LocalService, NetworkService, the SERVICE group, session 0) or another
  session's (the token's user isn't the user signed in to its session) are refused. A process
  created after the connection was accepted is refused too: a client that connects and exits
  can't hand its process id to whatever takes it next. The client connects at identification
  level, so the service can read who is asking but never act as them.
- The client checks the server: the pipe's server process (`GetNamedPipeServerProcessId`) must be
  the process the Service Control Manager says runs `TiresiasAdmin`. A program that created the pipe
  first, before the service started, is not the service, and the app says so instead of talking to it.

**Wire format**, version 1: as the agent pipe (`AgentWire`), one request and one reply per
connection, each a little-endian int32 length then UTF-8 JSON, at most 1 MiB.

```json
{ "version": 1, "op": "freeze", "args": { "pid": 4242 } }
{ "status": "ok", "result": { … } }       // or "refused" / "error", with "message"
```

An unknown op or version, a missing or extra argument, or a value out of range is refused before
anything is done (`AdminCallerPolicy`, in order: version, op, caller, elevation, whether this
service has the op yet, arguments). A refusal never repeats the caller's text.

The action log, `actions.jsonl` in the state folder, gets one line per request: format version,
time, op (or `unknown`), caller SID, process id, image path, result and the reason for a refusal.
Never an argument. It rolls over at 10 MB.

### Actions

| Op | Caller | Does |
|---|---|---|
| `status` | any | Version, protocol version, which features are on (decoys held, listening, auditing), counts only |
| `events.wait` | any | Waits up to 30 s for the caller's next events (decoy use, decoy read, freeze), then returns them; the app acknowledges by id. Events wait in the queue while the app is closed |
| `decoys.adopt` | any | Takes the caller's decoy set (as `decoys.json` holds it today) and the paths of its decoy files. The service listens on the set's ports, adds audit rules, and from then on the agent keeps no copy |
| `decoys.status` | any | The kinds placed and how many files, never paths, ports or values |
| `freeze` | any | Freezes a process of the caller's own user and the processes it started (below), and blocks its program's network. Used by the service itself on a decoy use; the app asks for it on **This wasn't me** |
| `thaw` | **elevated** | Undoes a freeze: thaws the processes, lifts the network block |
| `decoys.release` | **elevated** | Hands the set back (for `tir decoys remove` or removal of the tier), removes audit rules, stops listening |
| `lastrun` | any | For paths the caller names, when each last ran for the caller's user (Background Activity Moderator) and how often (Prefetch). Nothing about programs not asked for, nothing about other users |
| `teardown` | **elevated** | What remove does, before the service is deleted |

Machine-wide environment variables are **not** a service action: writing them affects every user
and every service, so the app does it through its own UAC prompt when the user asks. A service
doing it for an unelevated caller would be a privilege escalation.

## What each feature does

### Decoys held by the service

Placing is unchanged: the user's agent writes the decoy files, as the user (a SYSTEM process
writing into a user's profile can be steered by a junction). It then calls `decoys.adopt` and
deletes its `decoys.json`. The service writes the set to its state folder. Malware running as the
user can no longer read which files are decoys, the ports, or the values; it can still read the
decoy files themselves, which is the point.

`decoys.status` gives the app the kinds for Home's card, without places. `tir decoys list` shows
places only elevated.

### Listening from boot

The service binds the set's two ports on `127.0.0.1` at start, with the same listeners as the agent
(`DecoyListener`, `DecoyTds`), and names the caller from the TCP table. A hit becomes an event for
the user, and the service freezes the program at once (below). The app, when it runs, reads the
event and does what it does today: block list, notification, activity record, finding. With the
service holding the set, the agent does not listen.

### Every read named: auditing

On `decoys.adopt` the service adds a SACL entry to each decoy file (Everyone, `FILE_READ_DATA`,
success), opening it with `FILE_FLAG_OPEN_REPARSE_POINT` and checking it is a regular file owned by
the caller. It turns on the *File System* audit subcategory for success if it was off, and
remembers that so teardown can turn it off again.

It subscribes to the Security log for event 4663 on those paths. The event carries the process id
and image, so every read is named, every time, including the reads made while the app was closed
(the log keeps them). Routine openers (`DecoyReads.RoutineOpener`) are dropped as today. With
auditing on, the agent's oplock tripwire stands down for those files.

### Stopping the program

A decoy *use* freezes the program; a *read* never does, as today.

- **Freeze**: the service puts the process into a job object only SYSTEM can open, with every
  process it started that is still running, and freezes the job (`JobObjectFreezeInformation`).
  New children land in the job and are frozen with it.
- **Network**: Windows Filtering Platform filters, in a Tiresias sublayer, block connect and
  accept for the program's image path, IPv4 and IPv6, until lifted.
- **Undo**: Home's finding gets **Thaw**, which runs `thaw` (UAC). Dismissing the finding keeps it
  frozen. A frozen process holds its memory and handles; killing it stays the user's choice
  (Task Manager kills a frozen process).

To check before building: that `NtResumeProcess` from the user's own token does not thaw a job
freeze. If it does, the freeze also removes the user's `PROCESS_SUSPEND_RESUME` from the process's
DACL, and says the residual in the threat file.

### Last run

`lastrun` reads `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<caller SID>` and
the `C:\Windows\Prefetch\*.pf` files (decompressed with `RtlDecompressBufferEx`) for the paths
asked. [Attack surface](attack-surface.md) uses it for "last used"; a decoy finding uses it for
"first ran on".

## Offered where

- **First run**: one step after the vault, "Protect more with admin rights (optional)": what it
  adds in three lines, **Set up** (UAC) or **Not now**. Declining changes nothing.
- **About**: the tier's state (not installed, running, stopped, older than the app), with **Set up**,
  **Update** or **Remove**.
- **Doctor**: one line when installed: running, version, which features are on. When the service
  is installed but stopped, or runs but gives no answer from its own process, a failing check;
  older than the app, a warning.

Built in step 1, the first-run offer names the features to come and says they aren't in this
version yet. The Home finding **Update the admin tier** is not built yet: About and the doctor
line say when the service is older.

## Open questions

- **Over-the-shoulder elevation.** A standard user approves a UAC prompt with an administrator's
  password: the elevated caller is then the administrator, in the user's session, so the session
  rule refuses it, and its SID isn't the user's anyway. Install and remove don't use the pipe, so
  step 1 is unaffected; `thaw` and `decoys.release` (steps 2 and 4) need an answer, such as the
  elevated caller naming the user it acts for, accepted only from an administrator in that user's
  session.

## Build order

One PR each, merged before the next starts:

1. The service, its pipe, `status`, install, update and remove, first run and About, the action
   log. No features yet.
2. Decoys held and listened for from boot (`decoys.adopt`, `decoys.status`, `decoys.release`,
   `events.wait`).
3. Auditing reads (SACL, event 4663).
4. Freeze and network block, with `thaw`.
5. `lastrun` for attack surface and decoy findings.

Threats: [E-91](threats/E-91.md).
