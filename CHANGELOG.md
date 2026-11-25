# Changelog

What changed in each release of Tiresias, written for the people who use it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/). The NuGet packages are tagged `v<version>` and the
desktop app `app-v<version>`. Each release's notes on GitHub, and in the app's update dialog, are
its section below.

## [Unreleased]

### Changed

- **On a managed PC, only what you installed is checked.** When the PC is joined to a domain or to
  Microsoft Entra ID, or enrolled in device management, software installed for everyone is your
  administrator's: it stays under **Installed**, but raises no finding about log-on entries,
  uninstall entries or unused programs. A line in the checks says why. A blocked program is still
  reported wherever it is.

### Added

- **Browser and Visual Studio extensions are checked too.** Besides VS Code and its forks, the
  attack surface checks now read extensions in Edge, Chrome, Brave, Opera and Opera GX (every
  profile), Firefox and Visual Studio. One with an unknown publisher or no update in two years, in a
  program that used a credential through Tiresias, is a finding; since these programs have no
  command to remove an extension, its **Copy** button copies where to do it (`edge://extensions`,
  `about:addons`).
  `tir doctor --surface` lists them with their names.
- **Installed lists extensions and global tools.** **Show** now also picks **Extensions**, each
  with the program it runs in and what that program used through Tiresias in 90 days (those
  reaching most first), and **Global tools**, the day's listing of `dotnet`, `npm`, `pipx` and
  `cargo` tools. Read-only, like the rest of the page.
- **Startup** lists everything that starts when you sign in without being opened: the Run keys,
  the Startup folder and scheduled tasks with a sign-in trigger, those turned off too. Each entry
  shows the installed app it belongs to, or "Not from an installed app", which is the one worth a
  look, its signature, when you last opened it, and the services it used through Tiresias in 90
  days. **Turn off at sign-in...** keeps the program; **Show** picks entries not from an installed
  app, not signed or turned off.
- **Programs you built yourself** aren't a warning on a developer's PC. An unsigned program in a git
  work tree beside the project that builds it (`obj` next to its `bin`, or a project file above
  it), owned by you, is marked as your own build on Installed and Startup, and Home lists those that
  start at sign-in on one information line that opens Startup. A signature that doesn't verify, a
  program in Temp, Downloads or AppData, or a PC without developer tools keeps the warning.
- **Trust a publisher.** An unused program, an idle log-on entry or an old extension now offers
  **Trust *publisher*** beside **Dismiss** when a valid signature (or, for an extension, its
  marketplace publisher) says who made it, and so does the **Installed** panel. Its findings of
  that kind leave Home; blocked, unsigned or broken ones never do. Home's **Dismissed** lists each
  trusted publisher with **Stop trusting**.

### Changed

- **Dismissing an unused program, a log-on entry or an extension lasts through its updates**, and
  comes back when its signer changes or a new reason appears. Earlier dismissals still apply.
- **`tir doctor --surface` is quick again.** Listing the global `dotnet`, `npm`, `pipx` and `cargo`
  tools takes seconds, so it now happens once a day: the app does it in the background and keeps
  the list in `inventory.json` beside the keyring (names and versions only, on this PC only). The
  listing says when it was taken; `--refresh` lists the tools again now.

### Fixed

- **A paper recovery key with a misread S/5, Z/2, T/7 or U/V restores.** When the key as typed
  opens nothing, **Restore**, the first-run wizard and `tir recovery restore` try those letters the
  other way and take a reading only when it is this account's recovery key or opens a sealed item
  here. They then name each letter read differently, so you can correct the paper. Asking back
  two groups during setup forgives the same lookalikes.

## [0.4.1] - 2026-11-25

### Fixed

- **0.4.0 stopped at "Recovery setup is unavailable" for anyone who is not an administrator.**
  Reading the recovery enrollment asked Windows for write access to the local machine registry,
  which only administrators have, so first run, alerts and Activity all failed with "Attempted to
  perform an unauthorized operation." It now asks for read access only.

## [0.4.0] - 2026-11-24

### Added

- **Installed** marks unsigned and newly installed programs. Each program file's signature is
  checked in the background; one without a valid signature gets a caution mark, and one installed
  in the last 14 days a **New** mark. **Show** can pick either, and the details give the install
  date.
- **Devcontainers can ask instead of carrying secrets.** Put `"TIRESIAS_TICKET":
  "${localEnv:TIRESIAS_TICKET}"` in `remoteEnv` and start VS Code with `tir run -- code <folder>`:
  the devcontainer gets a ticket, and `tir-remote run -- <command>` inside it asks the Tiresias
  app for the folder's sealed variables when a tool needs them. The consent dialog names the
  devcontainer's folder; **Allow for the session** lasts until Tiresias locks. Needs Docker
  Desktop ([devcontainers that ask](docs/devcontainers.md)).
- **Git in a devcontainer asks for its token.** Map a host to a sealed token with
  `tir env git add github.com GH_TOKEN`, and add the feature
  `ghcr.io/hansen-consultancy/devcontainer-features/tiresias:0`: it installs `tir-remote` and makes
  it git's credential helper, so `git push` in the container asks the Tiresias app, which shows the
  host and the devcontainer's folder before handing the token over. `tir doctor`'s finding about
  VS Code forwarding your git credentials now points at it.
- **The app says why Windows is asking.** Just before each Windows Hello prompt, and before the UAC
  prompt for the admin tier, a small card above it names the reason: unlocking at start, the
  program that asked for secrets, the page you opened, the change you approved, the admin-tier
  step. Windows takes no text of ours in either prompt, so the card is where the reason goes.

### Fixed

- **Enrolling or replacing a recovery key needs an administrator's confirmation.** The paper key
  that can restore your sealed secrets is now recorded per Windows account in a store only an
  administrator can change. Setting one up or replacing it starts a small helper, `tiresias-recovery`,
  behind a UAC prompt; it shows the account and the old and new keys' fingerprints and changes
  nothing unless you answer Yes. Activity lists each approved or refused enrollment, so a program
  running as you can no longer swap in a paper key of its own unnoticed.
- The **Environment variables** page no longer ticks the decoy variables Tiresias placed
  (`ADMIN_API_URL`, `ADMIN_API_TOKEN`) as secrets to seal: they are listed as decoys and sealing
  passes them over, as do `tir env list` and `tir env protect`. A real variable of the same name, with another value, is still a secret. The
  page now opens with what is still in Windows, each heading says who can read what it lists, and
  the summary says what its count is out of.
- Updates no longer fail without a word. Programs the app starts no longer keep its install folder
  as their working folder, which blocked Velopack from swapping the files. Before applying an
  update, the app names any program still using that folder and asks you to close it. If an update
  still couldn't be applied, the next start says so instead of quietly running the earlier version.
- About scrolls, and its Developer tools and Admin tier cards are shorter; the Admin tier card says
  what the tier is for. Home's Decoys card lists one decoy per line, and the reach card's
  **Check daily** sits beside **Check now**. A finding's **Details** toggle stays readable when
  open. The user-secrets editor no longer shows a white grid in dark mode before you pick a project.
  Hovering a count in the side bar says what it counts.
- Home's trust chain check no longer says **Worth a look** after `tir trust bind-hello` when the
  broker runs as the Windows service: it asks the broker for its chain instead of reading a copy
  the service never updates. A check that says to run a `tir` command offers **Copy command**.
- **How to close it** shows its steps in the app instead of opening a web page: each command names
  your account, with **Copy**, and **Run as administrator** where it needs one.
- The user-secrets list marks each project's state (sealed, not sealed yet, settings only, empty)
  so they stand apart, and a line under it counts each. A sealed project with keys added beside it
  in plain since (`dotnet user-secrets set`) is marked amber until the next run seals them. A
  project whose secrets file holds only `tiresias:` references counts as settings only instead of
  "not sealed yet": a reference holds no secret, so `tir doctor` no longer warns about it either.

## [0.3.0] - 2026-11-23

### Added

- **The app stays simple on a PC that isn't a developer's.** Developer tools (Secrets, Services
  and Environment variables on Home, the developer needs, passing developer checks, the project
  decoy, the broker choice at setup) appear when the app finds something only a developer has,
  such as the .NET SDK, git or an IDE, and Home says once why. **Show developer tools** on About
  sets Auto, On or Off. Findings and warnings always show, and nothing you use is hidden.
- **Sealed variables for .NET apps an IDE starts.** `tir env config add <NAME>` (or
  `tir env protect --config`) lets a .NET app with `Tiresias.Extensions.Configuration` ask for a
  sealed variable itself, so F5 in Visual Studio or Rider gets it again after **Protect**. You
  allow each program, once or for the session; it reaches configuration with the same key and
  precedence as from your Windows environment.

- Selecting a row on Services, the secrets editor, Environment variables, About's alert sinks or
  the service incidents window shows it in full below the list, as Activity and Installed
  already did: values the narrow columns cut short wrap there, can be selected, and **Copy
  details** copies them. The secrets editor shows the key only, never the value.
- A critical alert, such as a used decoy credential, takes the LcdHub screen over in red with the
  event and its count, until Home shows your findings or for 24 hours. **Send a test alert** shows
  what it looks like for a minute.
- Alerts tell you when they stop arriving: a sink whose receiver refuses them, or that hasn't
  delivered for 15 minutes, is a finding on Home ("alerts to `phone` aren't arriving") and an
  "Alerts to a sink are failing" alert on your other sinks, whatever their threshold. Only a
  trusted sink learns which one is failing. The finding goes when the sink delivers again or you
  fix or remove it.
- Signed webhook alerts and a heartbeat: **Add a webhook...** can sign each alert the Standard
  Webhooks way, so the receiver can prove it came from your PC, and can send "Tiresias is running"
  every 5 to 60 minutes, so a receiver that expects it notices when alerts stop arriving. Both are
  off unless you turn them on, and the heartbeat carries only the PC's name and the time.
- More events raise an alert: a decoy file read, a blocked program asking again, a request refused
  in lockdown, "This wasn't me", a program asking for a secret while the PC is locked, the solo
  broker rejecting the trust chain, a paper key used, the vault rolled back or changed without your
  approval, an unapproved broker request (from the app's broker or the Windows service), a decoy the
  admin service holds being used, and new findings Home hasn't shown (a warning when one
  fails, info when they only warn). A program asking while you're at the PC still doesn't alert.
- Alerts on an LcdHub screen: **About**, **Alerts**, **Add LcdHub...** shows serious events as a
  line in the status strip of the LcdHub running on this PC, such as "Decoy credential used ×1",
  until Home shows your findings or for 24 hours. It shows only the event and its count.
- Alerts to your phone through ntfy: **About**, **Alerts**, **Add ntfy...** pushes the same events
  to an ntfy topic on ntfy.sh or your own server, with the severity as the notification's priority.
  The topic and an optional access token are sealed like a webhook's URL and saving needs Windows
  Hello; the form suggests a long random topic and a write-only token.
- Alerts to a webhook: **About**, **Alerts**, **Add a webhook...** posts serious events (today, a
  used decoy credential) as JSON to a URL you choose, so you hear about them when you aren't at the
  PC, even while it is locked. The URL and header are sealed like your secrets and saving needs
  Windows Hello; mute, remove and **Send a test alert** are on the same card. Alerts carry the
  event, its time and a name you give the PC, never a secret's name unless you mark the webhook
  trusted, and never a value.
- Home and `tir doctor` say when every program you run can open your Docker engine (and with it
  every container's environment), when you are in Hyper-V Administrators, and which WSL
  distributions' disks are files you own. Nothing inside a container, distribution or VM is read.
- `tir doctor --projects` and Home name secret-looking values written in your devcontainer files
  (`containerEnv`, `remoteEnv`, `runArgs` and the env files they name), with the commands to seal
  them and hand them in when VS Code starts the container; and they say when VS Code's Dev
  Containers forwards your git credentials or Docker logins into every container. Names only.
- `tir doctor --reach`, and **Check now** on Home's new containers card, look inside your Docker
  engine: which containers and images hold secret-looking names in their environment, and which
  containers mount your `.ssh`, `.aws` or other credential folders, with the commands to seal them
  and hand them in at start instead. Only when you ask (or daily, if you tick it); names only.
- The same look now reads your running WSL distributions too: AWS profiles, SSH keys, cloud and
  Kubernetes logins, registry logins, npm, PyPI and GitHub CLI tokens, and secret-looking `.env`
  names in each home, with the commands to seal them on Windows and pass them in through
  `WSLENV`. A stopped distribution is never opened, since that would start it.
- It also checks which Hyper-V disks, checkpoints and saved states your account can read without
  Hyper-V Administrators: a copy of one is the guest's files or memory, offline. Only the files'
  permissions are read, never the files. If you are in Hyper-V Administrators, it names the VMs
  the group opens.
- `tir solo service install` (as administrator) runs solo mode's broker as a Windows service under
  its own account, so programs running as you can't read its memory or rewrite the files it
  trusts, and an older `vault.json` restored while locked is refused. `tir solo service uninstall`
  moves it back into the app.
- `Tiresias.Core` and `Tiresias.Protocol` carry the groundwork for out-of-band alerts: the
  `tiresias.alert/v1` payload and the planner that decides, per sink, what to send, with dedupe,
  rate limits and redaction.
- Home and `tir doctor` list programs you haven't opened in 90 days. A program that works without
  being opened (a tray icon, a service, a driver, something that starts at log-on, a command on
  `PATH`) is never counted, nor one that used a credential. On Home they are one line, last, that
  doesn't light the tray badge.
- A new **Installed** page lists every installed program with when you last opened it (or why
  that's unknown) and its icon, unused ones first, with a search box. Select one to see its version, who it is
  installed for, the credentials it used in the last 90 days, its folder, its publisher and who
  signed it (checked on your PC), and **Search online...** to look it up in your browser. **Open Installed apps
  in Settings** is where you uninstall it.
- Admin tier: every read of a decoy file is named, from Windows' own file auditing, with the
  program that read it and what started it; reads by routine openers such as Windows Search are
  kept in the incident history and raise nothing.
- Admin tier: it now tells Tiresias when your programs last ran, from Windows' records only an
  administrator can read (the Background Activity Moderator and Prefetch), for the programs the
  doctor looks at and only for you. Unused applications are found more reliably, and a decoy
  finding says when Windows last saw the program run.
- Admin tier: a program that uses a decoy credential is now frozen, together with what it started,
  and cut off the network until you decide. Home's finding offers **Thaw and unblock (that was me)**
  behind an admin prompt, as does unblocking it from the blocked programs list; dismissing it keeps
  the program frozen. **This wasn't me** freezes the program too. Removing the admin tier thaws everything and lifts every network block first.
- `tir doctor --surface` also lists what is installed: each editor's extensions with the
  credentials that editor used through Tiresias in the last 90 days, global `dotnet`, `npm`, `pipx`
  and `cargo` tools, and what starts at log-on with its signature and when you last opened it.
- Home and `tir doctor` point out programs that start at log-on but that you haven't opened in 90
  days, with **Turn off at log-on...**: the same switch as Task Manager's Startup tab, so Settings,
  Apps, Startup turns it back on. Programs with a tray icon are never counted as unused, and
  entries already turned off there are no longer reported.
- Home and `tir doctor` check the installed-apps list against the disk: an entry for an app that
  is gone, an app whose uninstaller is missing (reinstall it over itself), and an older version's
  entry left after an update, whose **Uninstall** would remove the current version's files.
  **Remove entry...** saves the entry to a `.reg` file before removing it; machine-wide entries
  get the commands to run as an administrator.
- Decoy credentials: `tir decoys place passwords|project|variables` puts a `passwords.txt`, an old
  project's `appsettings.Production.json` and `.env`, or two user variables on disk, holding
  credentials that open nothing and point to ports only Tiresias listens on. A program that finds
  and uses one is named in the activity log while the app or `tir agent` runs. `tir decoys remove`
  takes them all away, and `tir doctor` warns when nothing listens.
- When a program uses a decoy credential, the app blocks it (no lockdown), shows a notification,
  and raises a finding on Home naming the program, with **Unblock (that was me)**.
- Decoy files are watched for opens too: while the app or `tir agent` runs, a program that opens
  `passwords.txt` or a decoy project's files is named in the activity log and raised as a warning
  on Home, with a notification. An open never blocks the program, and Windows Search, Defender,
  Explorer and OneDrive installed for all users opening them raise nothing. Openers that can't be told apart are recorded
  as unknown, never guessed.
- Home has a **Decoys** card: place `passwords.txt`, a decoy project or the decoy variables at
  their default places, each after asking first, see what is placed, and **Remove decoys**.
- Home and `tir doctor` find the GitHub CLI or the Azure CLI signed in as you, which any program
  running as you can use unasked. For `gh`, **Add a GitHub App...** sets up the service `tir exec`
  mints a token per run from, after you allow it. Read from each tool's own config, offline; never
  a token.
- The app checks for findings in the background, a minute after it starts and every four hours.
  New ones put a dot on the tray icon and "(*n* new)" on **Status...** until you open Home.
- Home and `tir doctor` ask RavenDB, through the broker, what each RavenDB service's certificate may
  do, and warn when it can change the server (Cluster Admin, Operator), reaches more than one
  database, or is Admin on its database. **Edit...** on the service swaps in a narrower one.
- An optional admin tier: with one Windows admin prompt, the app sets up a small Tiresias service
  that runs from Program Files. First run offers it once (**Not now** changes nothing); About shows
  whether it runs and offers **Set up**, **Update** or **Remove**, and `tir doctor` reports it.
  With it, your decoys are held by the service: programs running as you can no longer read which
  files are decoys or their values, a decoy used while the app is closed is caught from boot and
  shown when the app next runs, and Home and `tir decoys list` show the kinds held. Removing the
  decoys, or the admin tier, gives them back first (one more admin prompt). Every read of a held
  decoy file is seen through Windows auditing, even one made while the app was closed, and is
  shown as a read the app saw itself. Stopping the program comes in a next release.

### Changed

- Trust-chain links that add a device, user or broker, or change the admin threshold, now need a
  Windows Hello signature from each device that signs them and each device they add. Setting up
  solo mode asks for Windows Hello once more, to put this PC's Hello key in the chain. A chain made
  earlier keeps working; `tir trust bind-hello` (with the recovery key) adds the key to it, and
  `tir doctor` says when that is needed.
- While unlocked, the broker refuses a `vault.json` holding older versions of secrets than it
  already saw, as when an older copy is restored, and keeps the newer one.
- The broker now checks that you approved each placeholder, elevation and GitHub App token itself,
  instead of trusting any program that can sign as this PC. Approvals are signed with a key only
  the unlocked app or a Windows Hello prompt can derive; prompts are unchanged. Update `tir` and
  the app together: an older `tir` gets `approval-required`.
- The secrets editor hides user-secrets folders that hold no keys behind a line, "*N* empty
  folders", with **Move *N* empty to Recycle Bin**. Folders holding only settings (flags, numbers,
  plain URLs) say "(settings only)" and are listed after those holding secrets. Saving an empty file
  no longer seals it, and a sealed file that opens empty says so.
- Home and `tir doctor` list a settings-only `secrets.json` as passing ("holds settings, not
  secrets") instead of warning that it is in plain text. Dismissing a plain-text secrets file now
  lasts only until a key is added to it.

### Fixed

- The app's windows have the Windows 11 look (rounded buttons, cards, the light or dark theme)
  instead of the classic Windows style they fell back to.
- An app loading its user secrets through `Tiresias.Extensions.Configuration` now lets the
  consent dialog and Windows Hello prompt come to the front, as `tir` already did, instead of
  opening behind the IDE.
- Microsoft Defender for Endpoint's sensor opening a decoy file during a scan is recorded as a
  routine open, like Defender's own, instead of raising a warning on Home.
- The left menu is wide enough for "Environment variables" and its count, which it cut short
  as "Environment variab...".

## [0.2.1] - 2026-11-20

The desktop app's 0.2 release: everything listed under 0.2.0 below. The app's 0.2.0 build was
never published, because the release stopped while checking its signatures; the NuGet packages
were published as 0.2.0 and are unchanged.

### Fixed

- The app release now creates the folder it unpacks each package into before checking that the
  executables inside are signed.

## [0.2.0] - 2026-11-20

### Added

- `tir ai` prints instructions for AI coding agents (Claude Code, Codex, Copilot...): how to
  get credentials through `tir exec` and `tir run` without seeing them, and what never to do with a
  secret. `tir ai --install` writes a few lines into `~/.claude/CLAUDE.md` (or the file named,
  such as an `AGENTS.md`) so every agent session knows Tiresias is installed; installing again
  replaces them in place. `--snippet` prints them to paste by hand.
- `tir doctor` and the status page find git tokens in plain text: in a project's remote URL
  (`https://user:token@host`, with **Copy command** for the `git remote set-url` that takes it
  out) and in `~/.git-credentials`, counted by host. URLs are shown without the token.
- `tir doctor` and the status page find publishing keys: NuGet feed tokens in plain text or in a
  user environment variable, NuGet push keys, npm tokens and PyPI passwords in plain text. Each
  names the entry and the file, never the token. Feeds move to Tiresias as before; npm and PyPI
  tokens are sealed with the new `tir env import` (or **Seal token...**), which leaves `${NAME}`
  in the `.npmrc`. For nuget.org, npmjs.org and pypi.org the finding also points to trusted
  publishing from CI, which needs no key at all.
- A doctor fix's command (git remote, publishing keys) is offered only when the folder, entry,
  remote and URL it names hold letters, digits and `/:._@+-` alone, plus spaces and backslashes
  in a folder; otherwise the finding shows without one, so a crafted name can't run in your shell.
- `tir doctor` and the status page warn when a RavenDB service's certificate expires within 30
  days, and fail once it has, with **Replace certificate...** opening **Edit...** on the service.
  The expiry is recorded when a RavenDB is set up or edited; one set up earlier says "expiry
  unknown" until it is edited and saved once.
- The status page finds sealed API keys handed out as their value where a placeholder would do
  (an OpenAI-style key, or one with a matching vault service), and **Use a placeholder...** opens
  Environment variables with the key checked. It needs Tiresias unlocked; `tir doctor` skips it.
- The status page and `tir doctor` point out code that can reach your credentials and has a reason
  to be doubted: an extension from an unknown publisher, or unchanged for two years, inside an
  editor that used a credential through Tiresias in the last 90 days (**Remove...** uninstalls it
  after you approve), a program that starts at log-on without a signature, and a program you
  blocked with **This wasn't me** that is still on the PC (**Show file**). Nothing leaves the
  machine, and only names and metadata are read.
- **What do you need?** (**Add...** in the tray and the Services window) is the one way to add
  anything: pick or type what you need ("OpenAI key for a script") and see every way to meet it,
  strongest first, each saying what it gives up. Set up a SQL Server, Set up a RavenDB and the
  Services add form now open from there. What you type is matched on your PC and never sent.
  `tir advise "<words>"` prints the same list. The tray menu is shorter: Status, Add..., Activity.
  A dismissed SQL Server or RavenDB finding shows once more, as its fix now names Add....
- The status page shows **Add...**, and only the areas this PC uses: Secrets, Services,
  Environment variables and Activity appear once they hold something, or a finding leads there.

- The status page shows findings of one kind as one line with their count, for example
  "230 projects that set <UserSecretsId> but don't reference Tiresias.Extensions.Configuration". The
  line opens to each finding with its own fix, and **Dismiss all** sets them aside with one reason.
  Any check with a fix now counts as a finding too, such as a user secrets file that isn't valid JSON.

- The status page lists **findings** first: each says where a credential's delivery stands, where
  its fix takes it, and has a button that opens the fix filled in (Set up SQL Server with the
  server and database, Set up RavenDB with the certificate file and then an offer to move the file
  to the Recycle Bin, the secrets editor, Environment variables), or copies the command for a step
  outside the app. A finding can be dismissed with a reason; it stays dismissed until it changes,
  and `tir doctor` shows the reason too. The checks cover the project folders the secrets editor
  scans.

- **SQL Server logins in user secrets.** A `secrets.json` value `tiresias:sql/<service>/<grant>`
  becomes a temporary login for the lease when the app loads its configuration, and the app gets a
  new one before it expires (the reload token fires). No password stays in the file. A renewal
  declined on the consent screen is not asked again until the app restarts.
- **Set up a SQL Server** (Services window) prepares a database for those logins: an administrator
  signs in once, for that window only, and the service is saved with a `read` and a `write` grant.
- **RavenDB in user secrets.** A `secrets.json` value `tiresias:raven/<service>` becomes a URL on
  this PC that carries a placeholder in its path, so an unchanged RavenDB client works through the
  broker with no certificate on the PC.
- **Set up a RavenDB** (Services window) checks a client certificate against the database, then
  seals it in the vault and adds the server as a service. Its password is used only to open the
  file. **Edit...** changes such a service later (e.g. the Changes API) and keeps the certificate,
  so the file can be deleted once it is set up.
- **Edit...** in the Services window also changes an HTTP service added there: its upstream,
  secret, methods, paths and Windows Hello requirement. The name stays. Placeholders handed out
  for the old settings stop working, so programs using the service ask again.
- **How to use...** on the Services page shows again what to paste for a saved service: the
  user secrets line for a SQL Server or RavenDB, or a placeholder for an API key.
- RavenDB's Changes API works through the broker and the forwarder, for grants that list the
  `WEBSOCKET` method. Each tunnel is audited when it opens and when it closes, and closes with the
  lease.
- `tir exec` gives a SQL Server child its temporary login in `{SLUG}_CONNECTION_STRING`, for
  grants that hand out logins.
- **This wasn't me** on every consent dialog, for a prompt you didn't expect: it denies the
  request, locks Tiresias, ends the lease and refuses everything until you unlock from the app,
  and blocks the asking program until you unblock it on the status page. A follow-up window shows
  the program's folder, can end the process, and points to a Microsoft Defender scan; Activity
  records the process and what started it.
- The app starts when you sign in to Windows. The installer turns it on; the status page turns it
  off.
- An app with sealed user secrets (or `tiresias:` values) waits up to a minute for the Tiresias app instead of failing at
  once, so both can start at sign-in. A plaintext `secrets.json` without Tiresias loads as before,
  with no delay.
- `tir env nuget import`, and **NuGet feeds** in the environment variables window, move a feed's
  token out of NuGet.Config (`%NAME%` or plain text) into the sealed environment.
- The environment variables window can switch a sealed key to placeholder delivery and back.
- The `tir run` consent dialog shows the command line; the program's folder can be copied or
  opened in Explorer. The status window has an **Environment variables** button.
- A native Windows on Arm build: `TiresiasApp-win-arm64-Setup.exe` on each app release.
- **About Tiresias** (tray menu and status page): the version, where it runs from, since when, and
  this version's release notes, with links to GitHub.
- A development build says so: its tray icon has an orange corner, and the tray menu, tooltip,
  status page and About window name the version and commit. `tir status` shows which app it is
  talking to and which `tir` answered.
- Starting a different copy of the app (a development build while the installed app runs, or the
  other way round) offers to switch instead of only saying Tiresias is already running.
- **Restore with your recovery key.** On a new PC, or after Windows Hello was reset, the status page
  notices sealed secrets this Windows Hello can't open and offers **Restore**: type the paper key
  and they open again. Nothing is decrypted or re-encrypted. `tir recovery restore` does the same.
- The first run on a PC with sealed secrets copied from another one asks for their recovery key
  instead of making a new one.
- Environment variables that look like secrets can be sealed out of your Windows environment
  (**Environment variables** in the tray menu, or `tir env protect`), put back, and given to one
  program at a time with `tir run -- <command>`. The status page warns about the ones left exposed.
- A PowerShell profile hook (`tir env hook`) gives each terminal the sealed variables after you
  allow it once, and a variable can be kept for one folder (`tir env set NAME --folder`, or the
  folder field in the window): changing folder adds and removes its variables.
- `tir run --only NAME[,NAME...]` hands over just the variables named, instead of every one
  sealed for the folder.
- A sealed API key can be handed out as a placeholder instead of its value
  (`tir env placeholder add OPENAI_API_KEY openai`): terminals and `tir run` get a `tirph_`
  placeholder and the forwarder's address in `OPENAI_BASE_URL`, so the program never holds the key.
- `dotnet restore`, Visual Studio and Rider can take a private feed's token from a sealed variable
  (`tir env nuget add <source-url> <NAME>`), after you allow the program asking. Needs the .NET
  9.0.200 SDK or later.
- The secrets editor names projects instead of listing ids: add the folder you keep your code in
  under **Project folders**, use **Find a project**, or just run the project. Ids no project uses
  are grouped apart and can be moved to the Recycle Bin.
- **`tir doctor` findings.** A line about how a credential is delivered shows where it sits on the
  two axes, what can escape and who may use it unseen (`E5/C3` is readable and used silently), and
  where its fix takes it, with the fix as a command or a place in the app. New checks: a
  connection string with a password, in user secrets or (with `--projects`) `appsettings*.json`,
  offers per-lease SQL logins; a private key in a file, or a certificate path in configuration,
  offers having the broker present a RavenDB certificate. Passwords are never shown.

### Changed

- Home, the secrets editor, Services, Environment variables, Activity and About are now pages of
  one window, listed on the left, instead of separate windows. The whole window stays out of
  screenshots and screen shares. Escape on a page goes back Home.
- The window and the tray flyout now match the chosen design. Each place on the left shows its
  count (Activity shows today's), and About sits at the bottom. A lock in a circle, green while
  unlocked, sits beside the state. Findings are numbered, and the open one explains itself and
  shows where its fix takes it in green. The foot of Home is links: the checks passed, the
  dismissed, and Check again. Close is gone (Escape closes the window); Copy details and Open data
  folder are on About. The flyout shows today's approvals and Quit is a link.
- A left click on the tray icon opens a flyout: the lock state with Lock or Unlock, how many things
  could be safer (from Home's last check), and Add..., the secrets editor, Activity and Open
  Tiresias. The right-click menu is unchanged.
- Home leads with the next step: the lock state and **Add...** on top, then a heading that counts
  what could be safer ("3 things could be safer") over a bar of the checks that pass. The first
  finding is open with its fix as the main button; the others are one line each until you click
  one.
- The approval prompt is laid out in two columns: the question and its answers on the left, each
  answer with a line saying what it means, and what it gets, who is asking and the command line in
  a panel on the right. The usual answer is highlighted; Enter still approves nothing, and Deny
  keeps the focus.
- **Windows open where they should, at the size they keep**: each one opens centred on the
  window it came from, or on the screen, already at its final size. Home, Activity, Secrets,
  Services and Environment open at a fixed height instead of starting small and growing as their
  lists load; what arrives later scrolls. A finding has one small **Details** toggle instead of
  two full-width bars, and the findings' introduction is one short line.
- **Every window opens centred at a size that fits its content**: on the window that opened it,
  or on the monitor with the mouse, as tall as it needs up to most of the screen, in one of three
  widths. Home's top card is one line; the mode and **Start Tiresias when I sign in** moved to
  About, and a development build says "(dev)" in every title instead.
- **Home scrolls as one page**: findings, a group's members, dismissed findings and checks no
  longer scroll inside it. The first 20 findings show with **Show all**, and the checks that passed
  fold into one line. In the secrets editor, a project used by many worktrees is one line, such as
  "Shop (28 checkouts)", with the full list under **Show all**.
- **Ratings read as words**: findings and *What do you need?* show "Readable, unchecked → Stays in
  Tiresias, asks you" instead of `E5/C3 → E3/C1`, and pointing at them says what each word means.
  `tir` and Copy details keep the codes.
- **Summary first**: a finding shows what it is, where it stands and its fix; its detail and
  **Dismiss** are under **Details**. The environment variables window is one card per task, open
  when it has something to act on.
- **Saving, changing or removing a service asks you to approve it with Windows Hello**, after
  showing what changes (upstream, grants, paths), in the Services window, both setups and
  `tir service add`/`remove`. Its secrets are then bound to those settings: if a program edits the
  vault file to send them elsewhere, Tiresias refuses to use them until you approve the change.
  Secrets saved before this are refused until you approve them once: the app offers it after
  you unlock, `tir vault migrate` does it from a terminal, and `tir doctor` reports it.
- A development build no longer adds its `tir` to PATH, so it can't shadow the installed one.

### Fixed

- In *What do you need?*, opening the last group scrolls it into view instead of showing a sliver
  of it at the bottom.
- After **Copy details** in the problem dialog, the "Details copied" line no longer pushes the
  buttons out of the window.
- NuGet credential requests now show in Activity, with the program, the feed and the variable name
  (never the token): allowed, denied, handed over under an earlier allow for this session, a retry
  that wasn't answered, or a mapped variable that isn't sealed. The **App** source filter covers
  them, with user secrets and `tir run`.
- Windows Hello and consent prompts for `tir`, terminals and NuGet (Visual Studio) come to the
  front instead of opening behind your windows; when Windows keeps one back, it flashes in the
  taskbar. Several programs asking to unlock at once share one Hello prompt rather than stacking
  one each, and a Hello prompt answered too late says it expired instead of "Windows Hello failed
  (0x80098044)".
- The status page and `tir doctor --projects` look through the project folders once instead of six
  times, and skip build output, packages and git internals: on a drive of repositories the checks
  take seconds rather than half a minute. The findings list builds only the rows in view, so hundreds
  of findings show at once. The app logs how long the checks and showing them took.

- A placeholder limited to a grant that was later renamed or removed from its service is
  refused. Before, it could use every grant of the service, write and admin included.
- **Show** in the secrets editor reveals the value; it did nothing before.
- A selected row in the secrets, services and activity lists is a subtle highlight instead of dark
  blue under black text.
- The **Show** button in the secrets editor is wide enough for its text when the window opens.
- A `tiresias:` value in user secrets is fetched only after the consent screen, which shows each
  key with what it asks for (e.g. `ConnectionStrings:Db → tiresias:sql/appdb/read`). Before, the
  first load fetched it without asking, and Allow for this session also covered values changed
  later.
- When a service's settings change (upstream, methods, paths, which secret a grant uses), the
  placeholders and elevations approved for the old settings end. Before, they carried over to the
  new ones.

## [0.1.0-preview.4] - 2026-11-18

### Added

- `tir service add <slug> --upstream <https-url>` sets up a service for `tir exec` in one
  command: it asks for the secret's value if the vault doesn't have it yet, allows `GET` on every
  path unless you narrow it with `--method` and `--allow`, and refuses a plain-http address or a
  broken pattern with what to type instead. `tir service list` and `tir service remove` go with
  it. In solo mode the change works from the next request, with no lock and unlock, and a vault
  file that can't be read leaves the broker on its previous settings.
- The desktop app has a **Services** window (tray menu, and the status page) that lists the
  services `tir exec` can reach, adds one with the same checks as `tir service add` (explained
  beside the field that needs fixing), and removes one while keeping its secret. A new secret's
  value is typed into a hidden field in a window that stays out of screen shares.
- **Tiresias desktop app** for Windows 11, in the notification area. It unlocks with Windows Hello
  and shows whether you are locked or unlocked, and until when. It asks before anything gets a
  secret, in a dialog that shows which program is asking and which keys it gets, never their
  values. It also has a secrets editor that stays out of screenshots and screen shares, an activity
  window, a status page, and a first-run setup that is safe to close halfway.
- **Solo mode**: use Tiresias on one PC with no server. The broker runs inside the app on this PC
  only. `tir solo init` sets it up from the terminal.
- **Protected user secrets now work end to end.** With the app (or `tir agent`) running, an app's
  `secrets.json` is sealed the first time it loads. After that it gets its secrets only after you
  approve. Use "Allow for this session" to stop being asked until you lock.
  When Tiresias provides an app's secrets, the app prints one line saying so on its error output,
  with the number of keys and never their names or values.
- **Locked is no longer a dead end.** When an app asks for sealed user secrets while Tiresias is
  locked, the app shows who is asking with **Unlock with Windows Hello**, then the usual consent
  dialog, instead of the app stopping with "unlock first". An app now waits up to five minutes for
  that answer rather than three.
- The installer puts the app in `%LOCALAPPDATA%\TiresiasApp`, apart from your vault in
  `%LOCALAPPDATA%\Tiresias`, so uninstalling the app never deletes your secrets.
- The app puts `tir` on your user `PATH` when it starts, so `tir` works in any terminal you open
  afterwards, and takes it off again when you uninstall.
- `tir secrets list | set | remove` edits a project's protected user secrets without ever
  printing a value.
- When the app is running, `tir grant` and `tir exec` ask for approval in the app, `tir unlock`
  and `tir lock` work through it, and `tir status` shows its state.
- The app updates itself from GitHub Releases. It downloads in the background, shows what's new,
  and restarts only when you choose to.
- The app, `tir` and the installer are signed.
- A step-by-step guide to trying all of this on Windows: `docs/testing-on-windows.md`.

## [0.1.0-preview.2] - 2026-11-17

### Security

- Built on the .NET 11.0.0 packages, which fixes CVE-2026-120796 in System.Text.Json.

## [0.1.0-preview.1] - 2026-11-17

### Added

- First preview of the NuGet packages:
  - `Tiresias.Extensions.Configuration` is a drop-in replacement for `AddUserSecrets`. Your
    existing calls are rerouted at compile time, so you change no code, and secrets are asked from
    the Tiresias agent instead of read in clear.
  - `Tiresias.Core` is the vault, the trust chain, grants, leases and the audit log.
  - `Tiresias.Protocol` holds the wire formats.

[Unreleased]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.4.1...HEAD
[0.4.1]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.4.0...app-v0.4.1
[0.4.0]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.3.0...app-v0.4.0
[0.3.0]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.2.1...app-v0.3.0
[0.2.1]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.1.0-preview.4...app-v0.2.1
[0.2.0]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.1.0-preview.4...app-v0.2.0
[0.1.0-preview.4]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.2...app-v0.1.0-preview.4
[0.1.0-preview.2]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.1...v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/hansen-consultancy/Tiresias/releases/tag/v0.1.0-preview.1
