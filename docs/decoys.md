# Decoys: catching what goes looking for secrets

Status: **design, not built** (#39). Its alerts land as findings in [guided setup](guided-setup.md)
and use the program block list that **This wasn't me** already fills.

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
| An admin URL with a token | `passwords.txt`, a decoy `.env` (`ADMIN_API_URL`, `ADMIN_API_TOKEN`) | An HTTPS request to the agent's decoy HTTP listener |
| An API key with its base URL | A decoy `.env` (`OPENAI_API_KEY` beside `OPENAI_BASE_URL` on loopback) | A request to the same listener, on the path the SDK uses |
| A RavenDB URL | A decoy configuration file | A connection to a loopback port Tiresias listens on |

The values look like the real kind (a GitHub token's prefix and checksum, a key's length and
alphabet), never like a Tiresias placeholder (`tirph_`), which would give them away.

**On a hit**, the listener finds the connecting process from the TCP table, as the solo broker and
the forwarder already do, and Tiresias:

- records it in the activity log, with the decoy, the process path and its signer;
- shows a notification and badges the tray;
- adds the program to the block list, so it gets no lease, placeholder or consent dialog until the
  user reviews it;
- raises a finding on Home: **Unblock (that was me)** or **Keep blocked**, with the process's path,
  signature and parent.

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
| An oplock on the decoy, naming the reader by the thread that wakes when the oplock is released | No (to be proven) | **Second spike**: prior art (below) reports it naming the opener in about 0.1 s |

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

**False positives** are the cost of this layer: Windows Search, Defender, OneDrive and backup tools
open files they find. Decoys go in a folder those tools are told to skip where possible, and an
opener whose image is signed by a known indexer, antivirus or backup publisher is recorded, not
alerted on. A read alert never blocks a program by itself; it raises a finding, and the block
needs the user.

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
| Name the opener by the thread that wakes when the oplock is released | Would give layer 2 the name it lacks, without admin rights | Layer 2, second spike |
| Decoys for tools that **aren't installed**, so nothing legitimate reads them, retired when the real tool appears | Yes, for developer credentials pointing home: `~/.aws/credentials` with an `endpoint_url` on loopback, a `~/.kube/config` whose server is the HTTP decoy, a `pgpass.conf`. Only where the file doesn't exist (principle 4) | Layer 1, next |
| Different file names per install, from the names grabbers search for | Yes: `passwords.txt` is one fixed name today | Placement, next |
| A program using **several** decoys is a sweep: say so | Yes, as a fact in the finding ("used 3 decoys in 2 minutes") | Finding, next |
| Say whether the program is signed and where it runs from (Downloads, Temp) | Yes: the activity record has the signature; the finding should too | Finding, next |
| Freeze the process tree, cut its network | With admin rights only (above), undoable from Home; isolating the whole PC is not taken | Admin tier |
| Canary tokens registered with a public service | Yes, opt-in | Phase 3 |
| A fake browser profile, fake wallets and chat sessions | No: outside developer credentials | Not taken |

## Placement

- **What is placed:** `passwords.txt` in Documents, a decoy project folder with an
  `appsettings.Production.json` and a `.env`, and optionally a user environment variable with a
  decoy token. The user picks from a short list; nothing is placed silently.
- **Where:** the home folder and Documents by default, and inside the project folders the user
  gave the secrets editor, where an agent working on code is most likely to look.
- **Bookkeeping:** Tiresias records each decoy's path and value. The doctor's own checks skip
  them, so a decoy never shows up as a plaintext secret to seal.
- **Removal:** one action removes every decoy and stops every listener.

## Open questions

- **Loopback ports.** A fixed port per decoy kind is simpler but recognisable; a random port per
  install is less so. Where a forwarder runs (with a remote broker), its port could carry the HTTP
  decoys on decoy paths instead of a listener of their own; in solo mode there is none.
- **Agent not running.** With the app and `tir agent` both closed, nothing listens and a use goes
  unseen. The doctor says so while decoys are placed.
- **Agents in containers.** A container or WSL distribution reaches the host's loopback only when
  configured to. Decoys inside the container need their own endpoint there.
- **Sync.** Decoy files in a synced Documents folder reach other devices, where no listener runs.
  Prefer folders that don't sync, or say so.

## Phases

1. **Decoy credentials with loopback endpoints:** files, listeners, process identification, activity,
   block list, finding.
2. **Read tripwire:** naming the reader through Restart Manager is dropped; naming it through the
   thread that wakes is the second spike. With admin rights, auditing names every read (above).
3. **External canaries** (opt-in): decoys registered with a canary service, for use off the machine.
