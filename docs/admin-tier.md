# The admin tier: a privileged service, optional

Status: **all 5 steps built** (#91): the service, its pipe and `status`, install, update and
remove, the first-run and About offers, the doctor line and the action log; the decoys held and
listened for from boot (`decoys.adopt`, `decoys.status`, `decoys.release`, `events.wait`); every
read of a held decoy file audited; a program that used a decoy frozen and cut off the network
(`freeze`, `thaw`, `teardown`); and `lastrun` ([Build order](#build-order)).

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
  First, while the service runs, remove sends `teardown` (below). Then, whether or not it
  answered, remove stops the service, hands each user's set back to that user's `decoys.json` (as `decoys.release` does,
  below) and takes the audit rules off its files, then turns *File System* success auditing off
  again if the service turned it on and every set went back (`audit.json`), before deleting. The
  elevated remove process does this itself (`SeSecurityPrivilege`), so it works with the service
  stopped. It then undoes from `frozen.json` whatever freeze `teardown` didn't (the service didn't
  answer, or failed): thaws each job by name, lifts the filters, removes Tiresias's filtering
  provider. A set that can't go back, or a freeze that can't be undone, stays in the state folder,
  which is then kept, and the step reports failure; installing again picks it up.
- The elevated process reports back by exit code (`AdminSetupResult`): done, failed, files missing
  (a development build without the `admin\` folder), or set up but stopped again at once (the
  service found its state folder or pipe name not its own; the Windows event log says which).

## The pipe

`\\.\pipe\tiresias.admin`. The service creates it with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL
of SYSTEM full control, Authenticated Users read and write (not create), and NETWORK denied:
Authenticated Users includes callers over SMB, whose process ids mean nothing here. The next
instance is created before a connected one is served, so the name is never free for another
process to take. At most 32 connections are served at once; past that, callers wait, so long polls
held open by a program can't run the service out of handles.

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
| `status` | any | Version, protocol version, which features are on (decoys held, listening, auditing), and how many of the caller's freezes are in place; counts only |
| `events.wait` | any | Waits up to 30 s for the caller's next events (decoy use, decoy read; a use says whether it froze the program), then returns them; the app acknowledges by id. Events wait in the queue while the app is closed |
| `decoys.adopt` | any | Takes the caller's decoy set (as `decoys.json` holds it today) and the paths of its decoy files. The service listens on the set's ports, adds audit rules, and from then on the agent keeps no copy |
| `decoys.status` | any | The kinds placed and how many files, never paths, ports or values |
| `freeze` | any | Freezes a process of the caller's own user and the processes it started (below), and blocks its program's network. Used by the service itself on a decoy use; the app asks for it on **This wasn't me** |
| `thaw` | **elevated** | Undoes the session user's freezes of a program, named by its full path: thaws the processes, lifts the network block |
| `decoys.release` | **elevated** | Hands the set back (for `tir decoys remove` or removal of the tier), removes audit rules, stops listening |
| `lastrun` | any | For paths the caller names, when each last ran for the caller's user (Background Activity Moderator) and how often (Prefetch). Nothing about programs not asked for, nothing about other users |
| `teardown` | **elevated** | For remove: thaws every freeze, lifts every filter and removes the provider, stops listening, takes the audit rules off and the policy back. Until it restarts, the service then freezes and listens to nothing; the sets stay for remove to hand back once the service has stopped |

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

`decoys.status` gives the app the kinds for Home's card, without places, and `tir decoys list`
the kinds and file count. While the service holds a set, no other is placed beside it: the
agent refuses and says to remove the held one first. The agent offers the set when it is placed,
and at its start for decoys placed before the tier was installed; when the tier isn't running or
refuses, `decoys.json` stays and the agent listens, as without the tier.

**Handing back.** `decoys.release` stops listening, forgets the set and returns it, to an elevated
caller only: `tir decoys remove` and Home's **Remove decoys** start an elevated copy of themselves
(`tir decoys release`, `Tiresias.exe --admin-tier release-decoys`) through UAC. That process
writes the set to the session user's `decoys.json` (their profile's `AppData\Local\Tiresias`, from
the profile list when it runs as an administrator over the user's shoulder) as a **new file
only**, and checks the file's final path on its open handle: a link anywhere on the way, which the
user can make in their own profile, would steer an administrator's write, so such a file is
deleted again and the set is offered back to the service; if the service doesn't take it (stopped
meanwhile), the elevated process writes it to the state folder, where the service holds it again at
its next start. The unelevated agent then removes the
decoys as it always has. Not built: listing places elevated.

**Doctor.** With the set held, the decoys check counts the service as the listener (or warns
that a port is taken). It can no longer skip decoy files by place: a decoy `appsettings.json` or
`.env` may show as a file to seal. Decoy variables are still skipped (their names are fixed).

### Listening from boot

The service binds the set's two ports on `127.0.0.1` at start, with the same listeners as the agent
(`DecoyListener`, `DecoyTds`), and names the caller from the TCP table (the forwarder's
`TcpConnectionOwner`, linked) and the processes that started it. A set whose ports are taken (the
agent may hold them a moment after offering the set) is tried again every 5 s. A hit becomes an
event for the user, kept in the state folder (`events\<sid>.json`, the newest 100) until
acknowledged, so it survives the app being closed and the machine restarting. A hit by a process
it could name first freezes that process (below), before answering it (a quick caller would be gone by then), and the event says so. The agent, in the app or `tir agent`, long-polls
`events.wait` (30 s), and runs each event through the path of a use it saw itself: activity record
(consumer `decoy`), then block list, notification and finding in the app. It acknowledges by id on
the next wait. With the service holding the set, `decoys.json` is gone and the agent does not
listen.

### Every read named: auditing

**Rules.** On `decoys.adopt`, and again at each start for every held set, the service adds an
audit entry to each decoy file's SACL (Everyone, `FILE_READ_DATA`, success). It opens the file
with `FILE_FLAG_OPEN_REPARSE_POINT` and decides on that handle (`AdminAudit.RuleRefusal`): only a
regular file with one name, owned by the user whose set it is. A link, a folder, a hard link or
another owner's file (something the user swapped in to have SYSTEM change) gets no rule; the
service logs it and `decoys.status` reports `auditing` false for that user. Only Tiresias's own
entry is added or taken away; any other entry in the SACL stays.

**Policy.** The rules log nothing unless the *File System* audit subcategory audits success. The
service turns that on when it was off and remembers it did (`audit.json` in its state folder).
When the last set is released, or at start with no set held, it turns it off again, only if it
turned it on; one that was on before stays on. While on, any other SACL on the machine logs too:
that is Windows' setting, not Tiresias's, and it ends with the last set.

**Reading.** The service reads event 4663 from the Security log every 2 s (an `EventLogReader`: a subscription ignores the query's record id) from the last
record it handled, kept in `audit.json`: reads made while the service was stopped (or the machine
off) are read at its next start, as long as the log still has them. The first time, it starts at
the log's end. An event is a read when its mask has `FILE_READ_DATA` and it names a held file; it
becomes a `Read` event for that file's user, queued and fetched through `events.wait` like a
use, so the app does what it does for a read the tripwire saw: activity record and notification,
never a block. It names the process by the event's id and image; the processes that started it
only when the process now under that id started before the read (a later one has the id since).
Each program and file is reported once a minute (`DecoyHitFilter`).

**Routine openers.** `DecoyReads.RoutineOpener` decides as the agent does: Windows Search,
Defender, Explorer and machine-wide OneDrive by name and folder, recorded and raising nothing. For
Tiresias's own programs (`tir.exe`, `Tiresias.exe`) the folder is the decoy owner's
`%LOCALAPPDATA%\Tiresias`, from the profile list: that is where the app installs, and the folder
the agent vouches for when it watches itself. A program running as the user can write there, so
one named `Tiresias.exe` placed there reads unflagged; it is still in the activity log.

**The tripwire.** With the set held, `decoys.json` is gone and the agent's oplock tripwire
watches no file: the audit takes its place, and names every read where the oplock fired once.

### Stopping the program

A decoy *use* freezes the program; a *read* never does, as today.

- **Freeze**: the service puts the process into a job object, with every process it started that
  is still running (each started after its parent, so a reused parent id isn't followed), and
  freezes the job (`JobObjectFreezeInformation`, through `NtSetInformationJobObject`: the Win32
  `SetInformationJobObject` refuses that class). New children land in the job and are frozen with
  it. The job's ACL is SYSTEM and Administrators only; its name is `Global\Tiresias.Freeze.<guid>`,
  unguessable, since any user can create a job under a `Global\` name first.
- **Never frozen** (`AdminFreeze`, a pure planner): the idle and system processes, the service
  itself, a process of another user or whose owner or image can't be read, one Windows marks
  critical, Windows' session and shell processes run from the Windows folder (`csrss`, `winlogon`,
  `lsass`, `svchost`, `explorer`, `dwm`, `sihost`, `conhost` and the like), and Tiresias's own
  programs in its own folders. A refused descendant is left out; a refused process asked for
  refuses the freeze.
- **Network**: Windows Filtering Platform filters, in Tiresias's own provider and sublayer, both
  persistent, block connect and accept for the program's image path, IPv4 and IPv6, until lifted.
  One set per program: a second freeze of it adds none, and a thaw leaves the filters while another
  user's freeze of the same program still needs them.
- **Kept**: each freeze (user, program, job name, processes by id and start time, filter ids) is in
  `frozen.json` in the state folder, so a restart can still thaw and lift. The filters are
  persistent, so they survive a restart of the service or the machine. A job lives as long as a
  handle to it, but its *name* goes with the last handle, and a frozen process whose job can't be
  opened can only be ended, never thawed (assigning it to a second job and thawing that fails). So
  the service gives each frozen process a handle to its own job that allows only waiting
  (`SYNCHRONIZE`): the name lives as long as any of them runs, and `thaw` opens the job by name
  after the service restarts. A machine restart ends the processes anyway. While `frozen.json`
  can't be read, the service freezes nothing; a freeze it can't write there it undoes and refuses,
  and a thaw whose filters can't be lifted keeps them recorded and fails, so a retry lifts them.
- **This wasn't me**: the app asks `freeze` for the process it found, as the user; the service
  freezes it only when it is that user's, and the incident window says it is frozen.
- **Undo**: Home's finding gets **Thaw and unblock** instead of **Unblock**. Both, and unblocking a
  program on Home's list, run the app's `--admin-tier unblock-program <program>` (one UAC prompt),
  which runs `thaw` and then `blocks.unblock`; a failed thaw leaves it blocked. Dismissing the finding keeps it frozen. A frozen
  process holds its memory and handles; killing it stays the user's choice (Task Manager kills a
  frozen process).

**Checked by hand** (unprivileged, on the author's own child process): a job freeze set from the
user's own token is undone neither by `NtResumeProcess` (repeated) nor by `ResumeThread` on every
thread, from the user's own token; the job's thaw undoes it; `TerminateProcess` still ends a frozen
process. Resuming doesn't thaw, so the freeze leaves `PROCESS_SUSPEND_RESUME` in the process's
DACL. Not checked: the service's calls as SYSTEM with only the privileges it keeps, and the filters
on a real connection; those need the service installed.

**Residual**: a process started between the service's snapshot of the processes and the job's
assignment isn't in the job. A process running as the user can close the waiting handle inside a
frozen process (the user owns it); after a service restart that freeze can then only be ended, not
thawed. The filters match the image path: a copy of the program elsewhere isn't blocked.

### Last run

`lastrun` takes up to 256 drive-rooted paths, each a program or a folder (it covers the programs
under it), and answers at most 1024 programs. It reads the acting user's
`HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (the older
`bam\UserSettings` too): one value per program, named by its device path
(`\Device\HarddiskVolume3\...`), mapped to a drive path by each fixed or removable drive's device
name; other values and unmapped volumes are skipped. Then the `C:\Windows\Prefetch\*.pf` files of
those programs (MAM-compressed ones decompressed with `RtlDecompressBufferEx`, XPRESS Huffman;
versions 30 and 31), for the run count and the last 8 run times; Prefetch names volumes
`\VOLUME{<created>-<serial>}`, mapped by serial number. Parsed files are kept until they change.
The parsing is pure (`AdminLastRun`, `Prefetch`), checks every offset and size, and reads a damaged
file as nothing.

**Prefetch is the machine's**, every user's runs together, so it is added only to programs the
acting user's BAM lists: nothing for a path not asked, nothing for a program only another user ran.
BAM keeps about a week.

The agent's `IDoctorProbe.ProgramRuns` adds these runs to UserAssist's, marked not *opened*: a run
the user may not have started (at log-on, from a script). [Attack surface](attack-surface.md)
counts them for unused applications but not for log-on programs, which run at every log-on. It
asks about startup programs, installed programs' folders and blocked programs. A decoy finding says
when Windows last saw the program run.

## Offered where

- **First run**: one step after the vault, "Protect more with admin rights (optional)": what it
  adds in three lines, **Set up** (UAC) or **Not now**. Declining changes nothing.
- **About**: the tier's state (not installed, running, stopped, older than the app), with **Set up**,
  **Update** or **Remove**.
- **Doctor**: one line when installed: running, version, which features are on. When the service
  is installed but stopped, or runs but gives no answer from its own process, a failing check;
  older than the app, a warning.

The first-run offer names the features. The Home finding **Update the admin tier** is not built yet: About and the doctor
line say when the service is older.

## Over-the-shoulder elevation

A standard user approves a UAC prompt with an administrator's password: the elevated caller is
then the administrator, in the user's session, and its SID isn't the user's. **An elevated caller
acts for the user signed in to its session** (`AdminDecision.ActingFor`): `decoys.release` returns
that user's set, `thaw` thaws that user's program. An unelevated caller acts only for itself,
and only when it is that session's user. The alternative, the caller naming the user it acts for
in an argument, adds an argument to every op and a check that it names the session's user, and
gives nothing more: the session's user is the only one it could name. An administrator could read
the state folder anyway, so acting for the session's user grants nothing new.

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
