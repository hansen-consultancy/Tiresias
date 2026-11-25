# Attack surface: less software, less to trust

Status: **first slice, log-on use, uninstall-entry checks, unused applications, the Installed and Startup lists, own builds, `tir doctor --surface`, per-item dismissals and trusted publishers built** (#34, #55, #98, #108, #148); the rest is design. [Guided setup](guided-setup.md) phase 5: it builds on the
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

- GUI programs: UserAssist (per user: run count and last run), readable without admin. It records
  only what the user starts from Explorer, Start or the taskbar, so a program with an icon in the
  notification area (the taskbar's `NotifyIconSettings`) is used from there unseen: its last use is
  unknown.
- Anything, with the [admin tier](admin-tier.md#last-run) installed: its `lastrun` reads the
  user's Background Activity Moderator and Prefetch for the programs asked about. These runs count
  for unused applications, not for log-on programs (which run at every log-on).
- Command-line tools: the activity log and the terminal hook's records of what ran under
  Tiresias. File access times are not reliable on Windows and are not used.
- Extensions: their host's last use, and the extension folder's own install or update time.

What Windows doesn't record is shown as unknown, never guessed.

**Other extension hosts are read** (#107), each from its own metadata, never the extension's code:
Edge, Chrome, Brave, Opera and Opera GX from each profile's `Extensions\<id>\<version>\manifest.json` (the newest
version folder; a theme holds no code and is skipped; a name given as `__MSG_key__` is read from the
default locale's `messages.json`); Firefox from each profile's `extensions.json`, only what the user
installed and has on (`app-profile`, not disabled); Visual Studio from
`%LOCALAPPDATA%\Microsoft\VisualStudio\<version>\Extensions\*\extension.vsixmanifest`. The publisher
is the store a browser extension updates from (Chrome Web Store, Edge Add-ons, Opera add-ons; Firefox Add-ons when
Mozilla signed it), else unknown; for Visual Studio, the one its manifest names. None of these is a
marketplace publisher id, so trusting a publisher doesn't cover them. Last updated is the version
folder's creation time, Firefox's `updateDate`, or the manifest's write time. The same extension in
two profiles is one item. Unpacked browser extensions (loaded from a folder in developer mode) and
JetBrains and Notepad++ plugins aren't read yet. None of these hosts has a command to remove an
extension, so their findings carry `RemoveExtensionByHand`, which names the host's page
(`edge://extensions`, `about:addons`, **Extensions, Manage Extensions**); the app's **Copy** copies it.

**PowerShell modules installed for the user are read** (#107) as extensions of the shell that
loads them: `Documents\PowerShell\Modules` for PowerShell 7 (`pwsh.exe`) and
`Documents\WindowsPowerShell\Modules` for Windows PowerShell (`powershell.exe`), each module at its
newest version folder. The `PSGetModuleInfo.xml` that PowerShellGet and PSResourceGet leave beside
a module gives its version and install or update date (DTD prohibited); its publisher is the
PowerShell Gallery only when its source is `https://www.powershellgallery.com`, whatever the
repository is called, else unknown, as for a module copied in by hand. Their findings name
`Uninstall-PSResource` or `Uninstall-Module`.

**Uninstall entries are checked, not trusted.** An entry is only a claim that something is
installed. Each one is compared with the disk: the uninstaller its `UninstallString` names, its
`InstallLocation`, and whether another entry has the same uninstall command. The whole command,
not just the program: an installer engine or `rundll32` uninstalls many products, each with its
own arguments. Windows Installer entries (`msiexec`), Windows components and updates say nothing
about the program's files and are skipped; so is a duplicate whose versions can't be ordered. That is what finds the
entries below that no longer match anything. `EstimatedSize` is written once at install time and
is shown as such, never as space in use.

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
- **[OpenSSF Scorecard](https://scorecard.dev)** for desktop apps, which deps.dev doesn't
  cover: the project's repository, taken from its winget manifest, is looked up in the public API
  (`api.scorecard.dev/projects/github.com/<owner>/<repo>`). The checks that matter here are
  `Maintained`, `Code-Review`, `Signed-Releases`, `Vulnerabilities` and `Security-Policy`. A
  replacement is only suggested when it is maintained and has no open vulnerabilities, and the
  finding shows the score with those checks. The score helps decide; it doesn't prove the app is
  safe.

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
| Entry for software that is gone | Neither the uninstaller nor the install folder exists | `RemoveEntry(key)`; leftover data folders are listed, not removed |
| Installed, but can't be uninstalled | The program is present and its uninstaller is missing | `Repair(kind, id)`: reinstall the same version over it, which restores the uninstaller |
| Stale duplicate entry | Two entries have the same uninstall command, and one is for an older version | `RemoveEntry(key)` for the stale one. Its **Uninstall** button runs the current version's uninstaller, so the finding says not to use it |
| Desktop app with a web equivalent | The app is a wrapper around a site, or the site does what it does (mail, streaming, a device tool over WebUSB) | `ReplaceWithWebApp(id, url)` |
| Global tool rarely used | A global developer tool unused for 90 days | `RunOnDemand(kind, id)`: `dnx`, `npx`/`bunx` or `uvx` instead of a global install |
| Closed source with a trusted open replacement | A maintained open-source program does the same job (trust per *Trust*, Scorecard for the candidate) | `ReplaceWithOpenSource(id, candidate)`, suggested only |

Each fix is a `DoctorFix` like phase 1's, so the app opens the right place and `tir doctor` prints
the command. The new kinds:

- **`Uninstall`** and **`Update`** carry the exact command of the tool that installed the item
  (`winget`, `dotnet tool`, `npm`, `pipx`, `code`). The app runs it only after approval, never from a scan, with an
  argument list, never a shell string, because the package id comes from the machine.
  Machine-wide software says it needs an administrator, and the app starts it elevated only when
  asked.
- **`RemoveExtension`** uses the host's command where one exists (`code --uninstall-extension`).
  A browser has none, so the fix opens its extensions page instead.
- **`DisableStartup`** turns a user Run key or startup folder entry off after approval the way
  Task Manager and Settings do, in `StartupApproved`, so Settings, Apps, Startup turns it back on
  and the entry itself is untouched. Entries already off there aren't reported. Machine-wide
  entries open that Settings page, which asks for an administrator.
- **`RevealFile`** opens Explorer on the file. It is all Tiresias offers for a binary it can't
  attribute, because deleting an unknown file could break something the user needs.
- **`RemoveEntry`** exports the uninstall key to a `.reg` file in `removed-entries` beside the
  keyring, then deletes it; opening that file puts the entry back. A machine-wide key needs an
  administrator, so the app copies the commands instead.
- **`Repair`** is the installer's own reinstall of the installed version
  (`winget install --id <id> --exact --version <installed version> --force`); without
  `--version`, winget installs the latest. When winget no longer offers that version, the fix
  says so and offers the latest instead. It is offered before `Uninstall` whenever the uninstaller is missing, since removing by hand
  leaves shell extensions and services registered.
- **`ReplaceWithWebApp`** is a guide, not a command: install the site as an app from Edge or
  Chrome (Start menu, taskbar, own window, notifications, listed and removed like any app), check
  it works, then `Uninstall` the desktop app. Some sites only offer **Open in app** while the
  desktop app is installed; then the order is reversed and the finding says so. The browser that
  hosts web apps doesn't have to be the default one.
- **`RunOnDemand`** and **`ReplaceWithOpenSource`** carry the uninstall command plus the line to
  use instead; neither removes anything until approved.
  `ReplaceWithOpenSource` doesn't claim open source is safer. The gain is that its code and
  releases can be reviewed, while it still needs updating like anything else. A paid license or
  a habit the replacement doesn't match is a good reason to keep the app; the user says so once
  and the finding stays dismissed. Sometimes the right replacement is a slim tool of your own.

On a managed PC, surface findings cover what the user installed. Machine-wide software there is the
administrator's: it is listed under **Installed**, without a finding or a fix. This is built (#107).
A PC counts as managed when it is joined to an Active Directory domain or to Microsoft Entra ID
(`NetGetJoinInformation`, `NetGetAadJoinInformation`; a device only registered with a work account
is not), or enrolled in device management (a key under `HKLM\SOFTWARE\Microsoft\Enrollments`
with a `ProviderID` and `EnrollmentState` 1; Windows leaves other keys behind). All of it is
readable without admin rights. Machine Run key entries and machine-wide uninstall entries are then
left out of the startup, uninstall-entry and unused-application findings, and an `ok` line,
**managed PC**, says by what. A blocked program is still a finding wherever it is installed: it
already behaved like malware.

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

**Built** (#108), except the credentials reached:

- An extension, idle log-on or unused-program finding names its **item** (host and extension id,
  log-on entry, or uninstall key), its **reasons** and its **signer**. Its dismissal is keyed by
  the item, not the name, so it survives a version update; it records the signer and the reasons
  it accepted, and comes back when the signer changes (or loses its valid signature) or a reason
  it didn't accept appears. A reason gone keeps it dismissed. Every other finding keeps phase 2's
  key (name, fix, position).
- A **publisher** is the full Authenticode subject of a signature WinVerifyTrust accepts, checked
  offline; never the thumbprint (it changes at each renewal) and never the name an uninstall entry
  claims. An extension's publisher is its marketplace `publisherId`, never for a vsix or one with
  no known publisher.
- Trust hides only the findings that say an item is unused, idle at log-on, old or from an
  unverified publisher. Blocked, unsigned, broken-entry and vulnerability findings are never
  hidden by it. **Trust *publisher*** sits beside **Dismiss** on a finding whose items all share
  one publisher, and in the Installed panel for a program with a valid signature. Home's
  **Dismissed** lists each trusted publisher, with the findings it hides and **Stop trusting**,
  even when it hides none; the Installed panel offers **Stop trusting** too.
- `dismissals.json` is version 2: it adds `publishers` and the item fields. A version-1 file is
  read forward, its dismissals still matching by name; a newer one is dropped.

A dismissed blocked program stays blocked: the dismissal hides the finding, not the block, which
only **Unblock** lifts.

## What the probe reads

`IDoctorProbe` gains members, each read-only and without admin rights:

- **Installed items**: kind, id, version, install scope, publisher and signer, and for an
  extension its host program, from the sources under *Discovery*.
- **Last use** where Windows records it per user (UserAssist), and the activity log's last record
  per program. Prefetch and the Background Activity Moderator need an administrator: the admin
  tier's `lastrun` reads them, for the startup programs, installed folders and blocked programs
  asked (`Doctor.RunsAsked`), when installed.
- **Startup entries**: user and machine Run keys, startup folders, the user's scheduled tasks.
- **Credential use**: per program path, the services it asked for and when, from the local
  activity log. The log holds no values, so neither does this.
- **Whether the PC is managed.**

Trust facts don't come from the probe. The opt-in lookups fill a cache the planner reads, so the
planner stays pure and an offline machine gets the same findings minus those that need a source,
each saying "not checked online".

Listing every package manager takes seconds, so the inventory runs once a day and on request
(`tir doctor --surface --refresh`, **Check now**), not each time the app opens. The global tools'
listing is built that way (#107): the app's background checks, every four hours, list them again
once the last listing is a day old and keep it in `inventory.json` beside the keyring, names and
versions only and never sent anywhere; `tir doctor --surface` reads that listing, says when it was
taken, and lists again when it is a day old or with `--refresh`. A damaged file or one of another
format version is listed again rather than read. `tir doctor --surface` is
built: after the checks it lists each extension host with what it reached in 90 days and its
extensions, the global `dotnet`, `npm`, `pipx` and `cargo` tools (each manager given half a minute,
a missing one lists nothing), and what starts at log-on with its signature and last use.

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

## Field notes

From doing this by hand on a developer laptop, before any of it was built:

- **Broken entries are common.** About one in six user-installed applications had an entry
  pointing at a missing uninstaller: some were gone entirely, five were running daily with their
  uninstaller deleted (likely by a cleanup tool), and one was an old version's entry left after
  an update.
- **A stale duplicate is dangerous, not cosmetic.** Its uninstall command is the current
  install's, and running it removes the program files that aren't in use. The program keeps
  running until it is closed and then fails to start; the profile survives and `Repair` brings it
  back.
- **Access times arrive in bulk.** Many tools showed the same last access on one day, a backup
  or scan reading them, which is why *Discovery* doesn't use them.
- **Packaged callers see a private copy.** A command run from an MSIX-packaged app (some AI
  desktop apps are) writes `HKCU` and `AppData` into that package's private copy: an uninstall
  key deleted there is still in Windows. A fix must run outside the package, and a check made
  from inside one can report a change that never happened. Relevant if `Tiresias.App` is ever
  shipped as a package.
- **Some web equivalents are better than the app.** Device tools that talk USB or serial through
  the browser (WebUSB, Web Serial) replace whole desktop installs.

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
file**. **Log-on use is built** too: last use from UserAssist, and the "starts at log-on, rarely
used" finding with `DisableStartup`, never for a program whose last use is unknown, one with a tray
icon, or Tiresias itself. **Uninstall entries are checked** as well: user and machine entries
against the disk, raising the gone, can't-be-uninstalled and stale-duplicate findings, with
**Remove entry...** for the user's own entries and the commands for machine-wide ones; `Repair`
names winget's command once the inventory knows the package id, and the steps until then.
**Unused applications are found**: an installed program whose folder had nothing opened in 90
days (UserAssist, and with the admin tier the Background Activity Moderator and Prefetch), never one with no recorded run or one that runs unseen (a tray icon, a service,
a driver, a log-on entry, a folder on `PATH`), nor one that used a credential. It is a finding with
status `ok`, so it sorts last and doesn't count for the badge; all of them are one line on Home,
"*n* programs you haven't opened in 90 days", whose one button opens the **Installed** page. That
page is built too: every entry of the installed-apps list once (Windows Installer entries
included), for you or for everyone, its last opening or why its use is unknown (works in the
background, not recorded), and the credentials its folder's programs used in 90 days; unused
first, longest unused first. Two columns (program with the icon its entry names, last opened) fit any width; an icon is read
from a local file only, never a network path; selecting one shows
the rest below the list, and a search box matches every word against name, version, folder and
services. The selected program's panel also shows the publisher its entry claims and who signed
its program file (the `.exe` its icon comes from, else its uninstaller), checked offline with
WinVerifyTrust; a name from a signature that doesn't verify is shown as a
claim only. After the list shows, every program file's signature is checked in the background, a
few at a time, and a program whose file has no valid signature gets a quiet caution mark at the end
of its name; one that couldn't be checked (a part of Windows, a Store app, no file) is never called
unsigned. A program installed in the last 14 days gets a **New** mark: its entry's `InstallDate`
(`yyyyMMdd`), else when its own folder was created. **Show** picks all programs, not opened in 90
days, not signed, or installed in the last 14 days, and the summary counts each. It also picks
**Extensions** and **Global tools** (#107), which replace the programs in the list: each extension
with its host, publisher, last update and what its host reached in 90 days, those whose host
reached most first; each global tool from the day's listing with its manager, and the summary says
when it was listed. The search box matches them the same way. They have no signature, icon or
folder of their own there. **Search online...** opens the browser with a web search for the name and version, on
the user's click only; Tiresias itself sends nothing. Uninstalling goes through Settings, Apps, Installed apps
(`UninstallApp`) until the inventory knows each program's installer command.
**The Startup list is built** (#98), beside Installed: the user and machine Run keys and the
Startup folder, entries turned off in Task Manager or Settings included (marked **Off**), and the
scheduled tasks with a log-on trigger for anyone, the user or a group the user is in, read in process through the Task
Scheduler's COM interface (Windows' own `\Microsoft\Windows` tasks left out; none in demo mode).
Each entry names the installed app whose folder holds its program (the deepest one), or "Not from
an installed app", which sorts first; its last opening by the user (UserAssist), the credentials it
used in 90 days and its signature, with the same marks as Installed. **Turn off at sign-in...** is
`DisableStartup` for the user's own Run key and Startup folder entries that are on; machine-wide
entries and tasks go through Settings. **Show** picks all, not from an installed app, not signed
or turned off.
**Built by you** (#148): on a PC where [developer tools](developer-tools.md) show, a program with
no signature at all that sits in a git work tree (a `.git` folder or file walking up from it) that
also holds its project (`obj` beside its `bin`, or a `.csproj`, `.fsproj`, `.vbproj`, `.vcxproj`,
`.sln` or `.slnx` above it), and that the user owns, is information, not a caution: an info mark
on Installed and Startup (`Logic/ProgramMarks`, the one place both lists decide a mark), and the
"starts at log-on unsigned" finding becomes "built by you", status `ok`, one Home line "*n*
programs you built yourself that start at log-on" opening Startup. A signature that is present but
doesn't verify keeps its warning, and nothing in Temp, Downloads or AppData (with the browsers'
caches) qualifies. Detection reads names, folder listings and the file's owner, never starts
anything or needs an administrator. Without developer tools the finding reads as before
(`DoctorCheck.WithoutDeveloperTools`). Matching the repository's remote against owners the user
marks as their own is not built.
**Dismissals per item and trusted publishers are built** (#108), as [Dismissals](#dismissals)
says.
[Guided setup](guided-setup.md#phases) lists what is still design.

1. **Inventory**: applications, extensions, global tools and startup entries, with last use where
   known, as `tir doctor --surface` facts and the app's **Installed** list. No online lookups.
2. **Cross with credentials**: reach from the activity log, ranking, surface findings on Home,
   and the dismissals above, including trust per publisher.
3. **Trust lookups** (opt-in): deps.dev, OSV, marketplaces, winget-pkgs, Authenticode, Scorecard.
4. **Fixes**: approved uninstalls, updates, extension removal and startup changes.

Later, outside phase 5: **Isolation**, the placeholder environments for containers and WSL, and the
finding that suggests one when an agent or package manager is the program asking.
