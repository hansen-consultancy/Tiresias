# Decoys: catching what goes looking for secrets

Status: **phase 1 built** (#39): `tir decoys place|list|remove`, the agent's loopback endpoints,
the activity record, the doctor's line, the app's response (block, notify, finding), and Home's
**Decoys** card. The read tripwire is next. Its alerts land as findings in [guided setup](guided-setup.md)
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
  **Unblock (that was me)**; dismissing it keeps the program blocked. A process that couldn't be
  named can't be blocked: its uses in the last 30 days are one warning. The program's signature and parents are
  in the activity record, not yet in the finding.

The listener answers like the real service would refuse a bad password, so the caller learns
nothing. Nothing the decoy holds is ever valid anywhere.

**Limit:** a decoy that is read and sent off the machine, then tried elsewhere, is not seen. Only
an external canary service (a key that alerts when used anywhere) catches that, which means
registering decoys with a third party. That is a later, opt-in phase.

## Layer 2: tripwires on reads (spike first)

Seeing the read itself, before anything is tried, is harder on Windows without admin rights:

| Approach | Admin rights | Verdict |
|---|---|---|
| Last-access time, `FileSystemWatcher` | No | Unusable: no process, and access times are often not updated |
| Auditing with a SACL (Security log event 4663) | Yes, to set the audit policy and read the log | Works; offered only where the user is an administrator |
| Kernel ETW file events, a minifilter driver | Yes, or a driver | Out of scope |
| **An oplock on the decoy, plus Restart Manager** | **No** | **To be proven.** Tiresias holds an oplock on each decoy file; another process opening it breaks the oplock, and while the opener waits, Restart Manager (`RmGetList`) names who has the file open |

The spike answers: does the break fire for a read-only open, can the opener be named before it
continues, and how much does holding the oplock delay a legitimate opener?

**False positives** are the cost of this layer: Windows Search, Defender, OneDrive and backup tools
open files they find. Decoys go in a folder those tools are told to skip where possible, and an
opener whose image is signed by a known indexer, antivirus or backup publisher is recorded, not
alerted on. A read alert never blocks a program by itself; it raises a finding, and the block
needs the user.

An AI agent listing and reading files in the home folder will trip this layer. That is a reason to
have it, and a reason the wording must stay factual.

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
2. **Read tripwire spike:** prove or drop the oplock and Restart Manager approach; SACL auditing for
   administrators if it fails.
3. **External canaries** (opt-in): decoys registered with a canary service, for use off the machine.
