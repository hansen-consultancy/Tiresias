# Attack surface: less software, less to trust

Status: **first slice built** (#34, #55); the rest is design. [Guided setup](guided-setup.md) phase 5: it builds on the
findings `tir doctor` reports since phase 1 and the findings section, fixes and dismissals the app
gets in phase 2.

Every program installed runs as the user and can do what the user can, including ask Tiresias for
a credential. Each extension, plugin and global tool adds code from another publisher on the same
terms. The fewer there are, the fewer ways in. This page designs how Tiresias finds what is
installed and what extends it, judges which of it deserves trust, and suggests removing what isn't
used.

## What only Tiresias knows

An inventory tool can list software. Tiresias also knows **which programs use credentials**:
the activity log and consent records name every program that asked, for which service, and when.

That is what ranks the inventory. An extension runs with the rights of the program that loads it,
so when an editor holds a GitHub placeholder, every extension in that editor can use it. An
unused, unsigned plugin in a text editor is hygiene; an extension last updated years ago by an
unverified publisher, inside the editor that asks for the GitHub token every day, is a finding
with a reason to act.

Each finding therefore says three things: **what** it is, **what it can reach** (the credentials
its host program has asked for, from the activity log), and **why** it was flagged (unused,
unknown publisher, known vulnerability, unsigned).

## Discovery

Read-only, per user wherever possible, from sources each check can name:

| Kind | Sources |
|---|---|
| Applications | `winget list` and the uninstall registry keys (machine and user), Store packages |
| Runs without being started | Services, Run/RunOnce keys, startup folders, scheduled tasks |
| Extensions and plugins | VS Code and its forks (`--list-extensions --show-versions`, the extensions folder), Visual Studio's extension folders, Notepad++ `plugins`, browser extensions per profile (Edge, Chrome, Firefox), PowerShell modules installed for the user |
| Global developer tools | `dotnet tool list -g`, `npm ls -g`, `pipx list` and the user site-packages, `cargo install --list`, Go binaries in `GOPATH\bin`, `winget`-installed CLIs on `PATH` |

**Last used**, where Windows records it:

- GUI programs: UserAssist (per user: run count and last run), readable without admin.
- Anything with admin rights granted: Prefetch, the Background Activity Moderator.
- Command-line tools: the activity log and the terminal hook's records of what ran under
  Tiresias. File access times are not reliable on Windows and are not used.
- Extensions: their host's last use, and the extension folder's own install or update time.

What Windows doesn't record is shown as unknown, never guessed.

## Trust

Not a trust system of Tiresias's own. Existing sources, asked per package:

- **[deps.dev](https://deps.dev)**: npm, PyPI, NuGet, Cargo and Go packages, with OpenSSF Scorecard,
  maintainers, release history and advisories.
- **[OSV.dev](https://osv.dev)**: known vulnerabilities for an exact package and version.
- **Marketplaces**: VS Code Marketplace and Open VSX (verified publisher, installs, last update),
  browser extension stores.
- **winget-pkgs manifests**: publisher, version history and release dates, and a safety score from
  how mature the version is, how far it jumps and what kind of software it is. An existing winget
  scan-and-score engine does this today and is adopted as a library; its update flow is not.
- **Authenticode**: whether a binary is signed, and by whom.

**Privacy.** Asking an online source sends package names and versions off the machine. That is
**opt-in**, once, with the list of sources; only names and versions are sent, never paths, user
names or what asked for which credential; and each finding says which source it came from. Offline,
the checks still report what is installed, unused and unsigned.

## Findings

Guided setup's rule needs no widening: a finding is any check with a fix, plus any delivery with a
position (`DoctorCheck.IsFinding`). An installed program isn't a delivery, but every surface
finding below comes with a fix, so each is a finding on the first count.

**Surface findings carry no position.** Removing an extension changes who can reach a credential,
not how the credential is held: the placeholder the editor gets is still E3/C1 afterwards. Putting
a position on it would claim a move along an axis that didn't happen. Instead a surface finding
says in its detail what it can reach, the host program's services from the activity log, and its
reasons; reach orders the findings (*Ranking*) but doesn't decide whether a line is one. Each
check sets a `Kind` ("extensions from unverified publishers in programs that use credentials"), so
many findings of one kind show as one line, as phase 2 groups them. The one surface fix that does
move a delivery, taking a credential's use out of a host program, raises the delivery finding
guided setup already has for it, with that finding's position.

| Finding | Raised when | Fix |
|---|---|---|
| Extension in a program that uses credentials | The host asked Tiresias for a credential in the last 90 days, and the extension's publisher is unverified or unknown, or it was last updated over two years ago | `RemoveExtension(host, id)`; or `UseThroughBroker(host, service)`, opening *What do you need?* (phase 3) at that service, to move the use out of the host |
| Known vulnerability | OSV or the marketplace reports an advisory for the installed version | `Update(kind, id, fixed version)`, or `Uninstall` where no fixed version exists |
| Unsigned binary on `PATH` or at startup | No Authenticode signature, or one that doesn't verify | `RevealFile(path)`: show where it came from; `Uninstall` if its source is known |
| Not used in 90 days | Last use is known and older; never when last use is unknown | `Uninstall(kind, id)` |
| Starts at log-on, rarely used | A user Run key, startup folder entry or scheduled task, and the program is unused | `DisableStartup(entry)`, keeping the program |
| Blocked program still installed | **This wasn't me** or a decoy hit put it on the block list | `RevealFile(path)`, then `Uninstall` |

Each fix is a `DoctorFix` like phase 1's, so the app opens the right place and `tir doctor` prints
the command. The new kinds:

- **`Uninstall`** and **`Update`** carry the exact command of the tool that installed the item
  (`winget`, `dotnet tool`, `npm`, `pipx`, `code`). The app runs it only after approval, never from a scan, with an
  argument list, never a shell string, because the package id comes from the machine.
  Machine-wide software says it needs an administrator, and the app starts it elevated only when
  asked.
- **`RemoveExtension`** uses the host's command where one exists (`code --uninstall-extension`).
  A browser has none, so the fix opens its extensions page instead.
- **`DisableStartup`** changes a user Run key, startup folder entry or user scheduled task itself,
  after approval, and keeps what it changed so **Turn back on** can restore it. Machine-wide
  entries are reported with the command, not changed.
- **`RevealFile`** opens Explorer on the file. It is all Tiresias offers for a binary it can't
  attribute, because deleting an unknown file could break something the user needs.

On a managed PC (joined to a domain or enrolled in device management, both readable without
admin rights), surface findings cover what the user installed. Machine-wide software there is the
administrator's: it is listed under **Installed**, without a finding or a fix.

## Ranking

The activity log already decides what matters, so Home lists surface findings by reach first:

1. **Blocked programs**: something already behaved like malware.
2. **What reaches the most**: hosts ordered by the credentials they used in the last 90 days, an
   admin or elevation grant counting above a read grant. Within a host, a vulnerability comes
   before an unknown publisher, which comes before an old one or a missing signature.
3. **What reaches nothing but has a vulnerability or no signature** (on `PATH` or at startup).
4. **The rest**: unused software reaching nothing. It isn't listed one by one on Home; it is one
   line, "*n* programs unused for 90 days", opening the **Installed** list. That list is
   hygiene, not a warning, and doesn't count toward the tray badge.

Delivery findings and surface findings sit in separate groups, **How credentials are held** and
**What can reach them**. They answer different questions, and one ordering across both would rank
a plaintext password against an old browser extension.

## Dismissals

Most of what is installed is fine, so dismissing is the main thing people will do here. Surface
findings use phase 2's dismissals, a reason kept per finding, with two additions:

- **A dismissal names what it accepted.** It records the item, its publisher, the reasons
  present and the credentials its host used then. It comes back only for a reason it didn't
  accept: a new advisory, a publisher change, or the host starting to use a credential it hadn't. A version update alone doesn't bring it
  back, and "I use this yearly" stays dismissed.
- **Trust a publisher.** "I trust *publisher*" dismisses every finding whose only reason is
  that publisher's verification status or age, for every item signed by that publisher. A
  vulnerability is never covered by it. The trust is tied to the signing certificate's subject, so
  an item from a different signer is judged on its own.

The first slice needs neither: it puts the reasons in the finding's name, so phase 2's key (name,
fix, position) already brings a dismissal back for a new reason and keeps it through a version
update. The two additions don't fit that record. A new credential changes the reach, not the
name, and trust needs the publisher, so `Dismissal` gains the publisher, the accepted reasons and
the credentials reached, and matches on those for surface findings. That changes
`dismissals.json`, so its version bumps and the old file is read forward rather than dropped.

A dismissed blocked program stays blocked: the dismissal hides the finding, not the block, which
only **Unblock** lifts.

## What the probe reads

`IDoctorProbe` gains members, each read-only and without admin rights:

- **Installed items**: kind, id, version, install scope, publisher and signer, and for an
  extension its host program, from the sources under *Discovery*.
- **Last use** where Windows records it per user (UserAssist), and the activity log's last record
  per program. Prefetch and the Background Activity Moderator need an administrator and stay
  unused unless the user is one.
- **Startup entries**: user and machine Run keys, startup folders, the user's scheduled tasks.
- **Credential use**: per program path, the services it asked for and when, from the local
  activity log. The log holds no values, so neither does this.
- **Whether the PC is managed.**

Trust facts don't come from the probe. The opt-in lookups fill a cache the planner reads, so the
planner stays pure and an offline machine gets the same findings minus those that need a source,
each saying "not checked online".

Listing every package manager takes seconds, so the inventory runs once a day and on request
(`tir doctor --surface`, **Check now**), not each time the app opens.

## Tests

Planner cases, with a fake probe and a fake trust cache:

- an unverified extension in a host that asked for a GitHub credential last week is a finding
  ranked above an unsigned tool that reaches nothing;
- an item whose last use is unknown is never "not used";
- unused items reaching nothing collapse into the one summary line and don't count for the badge;
- a dismissal survives a version update and returns for a new advisory or a new credential its
  host starts using, and a version-1 `dismissals.json` still loads after the format bump;
- trusting a publisher covers its age and verification findings, not its vulnerabilities, and
  not an item from another signer;
- a blocked program ranks first and stays blocked when its finding is dismissed;
- on a managed PC, machine-wide software is listed but raises no finding;
- offline, findings that need a trust source are absent and the others say "not checked online";
- the lookup request holds names and versions only (a builder test: no paths, user names or
  services).

## Isolation

Not part of guided setup phase 5 (see *Phases*); kept here because it answers what removal can't.

Removing what isn't needed shrinks the surface; isolating what is risky but needed contains it.
Windows has no clean general answer: MSIX and AppContainer don't fit arbitrary programs, Windows
Sandbox is disposable, and a VM per tool is heavy.

The combination that works for the riskiest group, developer tools, package installs and coding
agents, is **a dev container or WSL distribution that holds no secrets and gets only
placeholders**. The tool can't reach the user's files or other programs, and what it holds is
useless outside the broker, which still asks before each lease and records each use. Tiresias's
part is to make that easy: a placeholder environment for a container (`tir exec` into
`docker run` / `wsl`), and a finding that suggests it when an agent or package manager is the one
asking for credentials.

## Open questions

- **Extension identity.** Can the broker tell which extension inside an editor made a request? It
  sees the process; extensions share it. Until it can, findings speak of the host program.
- **Thresholds per kind.** 90 days unused and two years since an extension's last update are
  starting points; dismissals absorb the exceptions until real use shows better numbers.

## What changed

The first version of this page predates the two axes and phase 1's findings. Three things moved:

- **Findings without positions.** Guided setup's findings were all deliveries until its rule
  became "a check with a fix, or a delivery with a position"; surface findings are findings by
  their fix, and reach only ranks them.
- **Scope on a managed PC** was an open question and is now decided: list machine-wide software,
  raise findings only for what the user installed.
- **Isolation leaves guided setup phase 5.** Placeholder environments for containers and WSL are a
  delivery feature of their own and ship separately; this phase only points at them once they
  exist.

## Phases

All of this is guided setup phase 5, built in this order. **The first slice is built** (#55):
offline only, it reads extensions of VS Code and its forks, the Run keys and Startup folder with an
offline Authenticode check, the blocklist, and reach from the activity and audit logs, and raises
the extension, unsigned-at-startup and blocked-program findings with **Remove...** and **Show
file**. [Guided setup](guided-setup.md#phases) lists what is still design.

1. **Inventory**: applications, extensions, global tools and startup entries, with last use where
   known, as `tir doctor --surface` facts and the app's **Installed** list. No online lookups.
2. **Cross with credentials**: reach from the activity log, ranking, surface findings on Home,
   and the dismissals above, including trust per publisher.
3. **Trust lookups** (opt-in): deps.dev, OSV, marketplaces, winget-pkgs, Authenticode.
4. **Fixes**: approved uninstalls, updates, extension removal and startup changes.

Later, outside phase 5: **Isolation**, the placeholder environments for containers and WSL, and the
finding that suggests one when an agent or package manager is the program asking.
