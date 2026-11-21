# Decoys: catching what goes looking for secrets

Status: **phase 1 built** (#39): `tir decoys place|list|remove`, the agent's loopback endpoints,
the activity record, the doctor's line, the app's response (block, notify, finding), and Home's
**Decoys** card. **Read tripwire built**: the agent holds an oplock on every decoy file and names
the program that opens one (layer 2). Alerts land as findings in [guided setup](guided-setup.md);
a use fills the program block list that **This wasn't me** fills, an open never does.

Consent stops a program using a credential through Tiresias without asking. It does nothing about
a program that searches the disk for credentials Tiresias never saw: malware, a compromised
package's install script, or an AI agent following instructions injected into a page it read.
Decoys turn that search into a signal: credentials and files that nothing legitimate touches, so
touching them names the program that did.

## Principles

1. **Detect use first, reads second.** A credential that is *used* is proof of intent and names
   the process that used it. A file that is *read* may be an indexer, a backup or the user.
2. **A decoy works nowhere.** It opens no real account or service and costs nothing if it leaks.
3. **No admin rights, no driver.** Everything here works for an ordinary user account, as the rest
   of Tiresias does.
4. **Decoys never break real tools.** Tiresias writes them only to files it creates, never into a
   file a real program reads (an existing `.aws/credentials`, `NuGet.Config`, `.gitconfig`), and
   removes them all on request.
5. **An alert says what happened, not more.** "*program* connected with the decoy password" is
   a fact; "*program* opened passwords.txt" is a fact that may be harmless. The wording keeps the
   two apart.

## Layer 1: decoy credentials that point home

A stolen key is only seen if its use reaches Tiresias. A decoy OpenAI key in a `.env` would be sent
to the real API and Tiresias would never know. So every decoy carries **its own endpoint, on
loopback, owned by Tiresias**, in the same place as the credential. The agent hosts these
listeners, as it hosts the solo broker, so they work in solo mode, where no forwarder runs, and
whether or not the app is in front:

| Decoy | Where it lives | What uses it |
|---|---|---|
| A connection string with a password | `passwords.txt`, a decoy `appsettings.Production.json` in a decoy project folder | Connects to a SQL listener on `127.0.0.1` that Tiresias runs |
| An admin URL with a token | `passwords.txt`, a decoy `.env` (`ADMIN_API_URL`, `ADMIN_API_TOKEN`) | An HTTP request to the agent's decoy HTTP listener |
| An API key with its base URL | A decoy `.env` (`OPENAI_API_KEY` beside `OPENAI_BASE_URL` on loopback) | A request to the same listener, on the path the SDK uses |
| A RavenDB URL | A decoy configuration file | A request to the same HTTP listener |

The URLs are plain `http://127.0.0.1:<port>`: a loopback HTTPS certificate would need trusting,
and a client that refuses plain HTTP is still seen connecting. The SQL listener answers pre-login
without encryption (the connection string says `Encrypt=False`), reads the login, and refuses it
with error 18456 as SQL Server does.

The values look like the real kind (a GitHub token's prefix and checksum, a key's length and
alphabet), never like a Tiresias placeholder (`tirph_`), which would give them away.

**On a hit**, the listener finds the connecting process from the TCP table, as the solo broker and
the forwarder already do. Any connection to a decoy port is a hit, since only a decoy names it; the
record says which value was presented (the SQL password, the admin token, the API key) or that none
was. Repeats by the same program with the same value within a minute are one hit, so a flood of
connections can't bury the first in the log or the notifications. Tiresias then:

- records it in the activity log (`consumer: decoy`), with the decoy, the endpoint, the process and
  the processes that started it, never a value (`tir agent` also prints it);
- in the app, adds the program to the block list, without the lockdown **This wasn't me** brings,
  so it gets no lease, placeholder or consent dialog until the user reviews it;
- shows a notification;
- raises a finding on Home (`tir doctor` too) naming the program and the decoy it used, with
  **Unblock (that was me)**, or **Thaw and unblock** when the admin tier froze it; dismissing it
  keeps the program blocked. A process that couldn't be
  named can't be blocked: its uses in the last 30 days are one warning. The program's signature and parents are
  in the activity record, not yet in the finding.

The listener answers like the real service would refuse a bad password, so the caller learns
nothing. Nothing the decoy holds is ever valid anywhere.

**Limit:** a decoy that is read and sent off the machine, then tried elsewhere, is not seen. Only
an external canary service (a key that alerts when used anywhere) catches that, which means
registering decoys with a third party. That is a later, opt-in phase.

## Layer 2: tripwires on reads

Seeing the read itself, before anything is tried, is harder on Windows without admin rights:

| Approach | Admin rights | Verdict |
|---|---|---|
| Last-access time, `FileSystemWatcher` | No | Unusable: no process, and access times are often not updated |
| Auditing with a SACL (Security log event 4663) | Yes, to set the audit policy and read the log | Works; offered only where the user is an administrator |
| Kernel ETW file events, a minifilter driver | Yes, or a driver | Out of scope |
| An oplock on the decoy, naming the reader by Restart Manager | No | **Dropped** after a spike: it sees a read but can't say who read it (below) |
| **An oplock on the decoy, naming the reader by the thread that wakes when the oplock is released** | **No** | **Works** (second spike, below): never named the wrong process |

**The oplock spike** (Windows 11, NTFS, ordinary user; 5 oplock levels, 2 share modes, 11 kinds of
opener, each in its own process):

- **The break fires on a read** with a read-handle-write (RWH), read-write (RW), Level 1 or batch
  oplock and a file shared for everything, and the break says it was a read (the opener's access
  mask). A read oplock (RH) on a shared file does not break: read oplocks are shared. Without
  sharing, an RW or Level 1 oplock just fails the reader with a sharing violation, which is neither
  detection nor harmless. Metadata (attributes, `dir`, Explorer's details) breaks nothing.
- **The opener can't be named while it waits.** It has no handle yet, so asking Windows which
  processes use the file (`FileProcessIdsUsingFileInformation`) returns none, even with the break
  held for two seconds. Restart Manager opens the file itself, so it queues behind the break and
  deadlocks the holder. After the break is acknowledged, only a reader that keeps its handle open
  is seen; `type`, `Get-Content` and `File.ReadAllText` close it first and never were.
- **It fires once.** After a break, later reads don't break again until every other handle has
  closed and the oplock is taken anew.
- Holding the oplock costs a legitimate reader about a millisecond.

So an ordinary user can learn that *something* read a decoy file, once, but not what. Without a
name, the indexer, antivirus and backup openers below can't be told apart from a thief, so the
signal would be mostly noise. A read alert without a name would break principle 5, so this way of
naming the reader was dropped. For now, files are covered only when a credential in them is *used* (layer 1).

**The second spike** (method from prior art, below; ordinary user, no privilege): when the oplock
breaks, the opener's thread is stuck in a wait that began at that tick. Tiresias lists every thread
on the machine (`NtQuerySystemInformation`, which shows state and wait start even for processes
it can't open), keeps those waiting since the break and unchanged across two snapshots, releases
the oplock, and looks again: the thread whose wait ended is the opener. If threads of more than one
process woke, it says it can't tell rather than guess.

- 295 opens from separate processes (`type`, `Get-Content`, `File.ReadAllText`, a raw read):
  267 named correctly, 28 "can't tell", **none wrong**. Busy processes doing file I/O alongside never
  became candidates. The "can't tell" cases were long-waiting threads that happened to wake at the
  same instant (OneDrive's sync service most often).
- The reader waits about 55 ms (snapshots 20 ms apart) to 90 ms; unarmed, under 1 ms. Naming takes
  15 to 20 ms after the release. The reader still gets the file: this layer names, it doesn't stop.
- Elevated and SYSTEM openers are seen too: a same-user elevated process by path, a service by
  image name only.
- Short-lived openers exit within milliseconds, so the name comes from the thread list itself, not
  a later lookup. A program that opens a file for another (Explorer's preview, Defender, the indexer)
  is named as itself: right process, innocent identity, which is why the publisher check below matters.
- An attacker can force "can't tell" by waking a helper at the same moment; it can't make Tiresias
  name the wrong program. Each break uses the oplock up; it is taken again within about 0.15 s.

**What is built.** While the app or `tir agent` runs, the agent holds an oplock on each decoy
file placed (`passwords.txt`, the decoy project's `appsettings.Production.json` and `.env`; the
variables have no file), and names openers as above: settle 20 ms, two snapshots, release, a look
3 ms later. Each file has its own thread, which takes the oplock again as soon as the opener's
handle allows. A file that is gone or can't be opened is logged and left unwatched until
`decoys.json` changes. The opener's full path is read while it waits, by pid
(`SystemProcessIdInformation`, which works for services and Defender too); one whose path can't be
read keeps the thread list's file name. Each open:

- is in the activity log (`consumer: decoy`, `service: opened the decoy file passwords.txt`, the
  file's path, `{image} (pid N)` or no process when Tiresias can't tell), once per program and file
  a minute;
- raises a finding on Home and in `tir doctor`: a warning per program that opened one in the last
  30 days ("*program* opened the decoy file .env"), with **Show file** when its path is
  known; opens Tiresias couldn't name are one warning. A program already blocked for using a decoy
  gets no second finding;
- shows a notification in the app when a named program that isn't routine opened it. An open
  **never blocks** a program by itself; the block needs the user.

**False positives** are the cost of this layer: Windows Search, Defender, OneDrive and backup tools
open files they find. A routine opener is recorded but raises nothing: Windows Search
(`SearchProtocolHost`, `SearchIndexer`, `SearchFilterHost`) and Explorer (`explorer`, `prevhost`)
under `%WINDIR%`, Defender (`MsMpEng`, `MpDefenderCoreService`) under `%ProgramFiles%` or
`%ProgramData%\Microsoft\Windows Defender`, OneDrive's machine-wide install under `%ProgramFiles%`,
and Tiresias's own `tir` and app (removing decoys reads them). A per-user OneDrive runs from a folder
any program can write to, so its opens are findings: keep decoys out of synced folders. Both the
file name and the folder must match; an opener whose path couldn't be read is not routine. Checking
the publisher's signature, and backup tools, are not built yet. Decoys go in a folder those tools
are told to skip where possible.

An AI agent listing and reading files in the home folder will trip this layer. That is a reason to
have it, and a reason the wording must stay factual.

## With admin rights (optional)

Everything above works for an ordinary user, and stays that way. A user who can approve one UAC
prompt gets more, through the same step that installs the broker as a Windows service
([desktop app](desktop-app.md#what-runs-where)): one service, not a second installer.

| Gain | Why it needs admin |
|---|---|
| **The decoys' secrets stay out of reach.** Malware running as the user can read `decoys.json` today, learn the two ports and the values, and steer around them. Held by the service, under its own account, it can't | A service account's files and memory are closed to the user's processes |
| **Listening while the app is closed**, from boot: no "nothing listens" gap | Installing a service |
| **Every read named, every time**, by auditing: an audit rule on each decoy file, read from the Security log (event 4663). Repeatable where the oplock fires once, and it covers openers that avoid an oplock break. The log keeps what happened while Tiresias wasn't running | Setting audit rules and the audit policy, and reading the Security log |
| **Stopping the program, not only refusing it**: suspend it and what it started in a job object the user can't thaw, and cut its network (Windows Filtering Platform) until the user decides | Suspending another process and adding firewall filters, from a privileged service |
| Richer facts for the finding: process start history (Prefetch, Background Activity Moderator), as [attack surface](attack-surface.md) wants too | Both need admin to read |

**Built (step 2 of [the admin tier](admin-tier.md)).** With the tier installed, the agent places
the decoys as before, then hands the set to the service and deletes `decoys.json`; the service
listens on its ports from boot and queues each use until the app (or `tir agent`) takes it, which
then blocks, notifies, records and raises the finding as for a use it saw itself. Home and
`tir decoys list` show the kinds held, not the places. `tir decoys remove` and **Remove decoys**
take the set back through a UAC prompt, then remove the decoys as always. While a set is held, no
other is placed beside it. **Step 3**: the service puts an audit rule on each held decoy file and
reads every read of one from the Security log, including reads while the app or the service was
stopped; each comes to the app as a read the tripwire saw (recorded, notified, never blocked).
**Step 4**: a use by a process the service can name freezes it, with what it started, and blocks
its program's network until the user thaws it from Home (a UAC prompt); **This wasn't me** asks the
service to do the same.

**The cost.** A privileged service is the most valuable thing on the machine to attack: a bug in it
is a privilege escalation. It stays small, takes requests only from the app, does only the
actions above, and the parts that read or suspend user processes run as SYSTEM only if the
virtual account can't do them. Every action it takes is in the activity log and undoable from
Home.

## Prior art: A Better Antivirus

[A Better Antivirus](https://github.com/vulnix0x4/a-better-antivirus) (MIT) plants bait files for
infostealers and freezes the program that opens one. It watches reads, runs a SYSTEM service and
sets audit rules; Tiresias watches use and needs no admin rights. What fits Tiresias:

| Idea | Fit | Where |
|---|---|---|
| Name the opener by the thread that wakes when the oplock is released | Yes: proven without admin rights | Layer 2 |
| Decoys for tools that **aren't installed**, so nothing legitimate reads them, retired when the real tool appears | Yes, for developer credentials pointing home: `~/.aws/credentials` with an `endpoint_url` on loopback, a `~/.kube/config` whose server is the HTTP decoy, a `pgpass.conf`. Only where the file doesn't exist (principle 4) | Layer 1, #92 |
| Different file names per install, from the names grabbers search for | Yes: `passwords.txt` is one fixed name today | Placement, #92 |
| A program using **several** decoys is a sweep: say so | Yes, as a fact in the finding ("used 3 decoys in 2 minutes") | Finding, #92 |
| Say whether the program is signed and where it runs from (Downloads, Temp) | Yes: the activity record has the signature; the finding should too | Finding, #92 |
| Freeze the process tree, cut its network | With admin rights only (above), undoable from Home; isolating the whole PC is not taken | Admin tier, #91 |
| Canary tokens registered with a public service | Yes, opt-in | Phase 3, #93 |
| A fake browser profile, fake wallets and chat sessions | No: outside developer credentials | Not taken |

## Placement

- **What is placed:** `passwords.txt` in Documents, a decoy project folder (a new folder,
  `%USERPROFILE%\source\billing-api-old` by default) with an `appsettings.Production.json` and a
  `.env`, and optionally the user environment variables `ADMIN_API_URL` and `ADMIN_API_TOKEN`. The user picks
  from a short list (`tir decoys place passwords|project|variables [<path>]`); nothing is placed
  silently, and a file, folder or variable that exists is refused.
- **In the app:** a **Decoys** card on Home, below the blocked programs, lists what is placed and
  offers each kind not yet placed as a link (**Place passwords.txt**, **Place a decoy project**,
  **Set decoy variables**) at its default place, plus **Remove decoys**. Each asks first, saying
  what will be created; the page keeps its one button row (app-design.md, section 11). Another
  place is `tir decoys place <kind> <path>`'s. Considered and not taken: an entry in **What do you
  need?** (its catalogue is of things to protect, and a decoy protects nothing, so it doesn't fit
  the Exposure/Control model), a finding offering decoys (a finding is something wrong, and having
  none isn't), and the command line only (most users never open it).
- **Where:** the home folder and Documents by default, and inside the project folders the user
  gave the secrets editor, where an agent working on code is most likely to look.
- **Bookkeeping:** Tiresias records each decoy's path, the values and the two ports in
  `decoys.json` beside the keyring. The doctor's own checks skip them, so a decoy never shows up as
  a plaintext secret to seal.
- **Removal:** one action (`tir decoys remove`) removes every decoy and stops every listener. A
  decoy folder is deleted only when nothing else is in it, and a decoy file or variable changed since
  it was placed is kept: it is the user's now. A placement that fails partway takes back what it
  wrote.

## Open questions

- **Loopback ports** (decided): two random ports per install, one HTTP and one SQL Server, chosen
  when the first decoy is placed. A fixed port would give Tiresias away.
- **Agent not running** (decided): with the app and `tir agent` both closed, nothing listens and a
  use goes unseen. `tir doctor` warns while decoys are placed and nothing listens, checking the
  listening ports without connecting (a connection would be a hit).
- **Agents in containers.** A container or WSL distribution reaches the host's loopback only when
  configured to. Decoys inside the container need their own endpoint there.
- **Sync.** Decoy files in a synced Documents folder reach other devices, where no listener runs.
  Prefer folders that don't sync, or say so.

## Phases

1. **Decoy credentials with loopback endpoints:** files, listeners, process identification, activity,
   block list, finding.
2. **Read tripwire** (built): an oplock on each decoy file, naming the reader by the thread that
   wakes, activity, finding, notification. With admin rights, auditing names every read as well (#91).
3. **External canaries** (opt-in): decoys registered with a canary service, for use off the machine.
