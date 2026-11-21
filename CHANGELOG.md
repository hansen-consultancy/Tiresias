# Changelog

What changed in each release of Tiresias, written for the people who use it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/). The NuGet packages are tagged `v<version>` and the
desktop app `app-v<version>`. Each release's notes on GitHub, and in the app's update dialog, are
its section below.

## [Unreleased]

### Added

- Home and `tir doctor` list programs you haven't opened in 90 days, with **Open Installed apps**
  to uninstall them. A program that works without being opened (a tray icon, a service, a driver,
  something that starts at log-on, a command on `PATH`) is never counted, nor one that used a
  credential. These lines sort last and don't light the tray badge.
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
- Home and `tir doctor` find the GitHub CLI or the Azure CLI signed in as you, which any program
  running as you can use unasked. For `gh`, **Add a GitHub App...** sets up the service `tir exec`
  mints a token per run from, after you allow it. Read from each tool's own config, offline; never
  a token.
- The app checks for findings in the background, a minute after it starts and every four hours.
  New ones put a dot on the tray icon and "(*n* new)" on **Status...** until you open Home.

### Changed

- The secrets editor hides user-secrets folders that hold no keys behind a line, "*N* empty
  folders", with **Move *N* empty to Recycle Bin**. Folders holding only settings (flags, numbers,
  plain URLs) say "(settings only)" and are listed after those holding secrets. Saving an empty file
  no longer seals it, and a sealed file that opens empty says so.
- Home and `tir doctor` list a settings-only `secrets.json` as passing ("holds settings, not
  secrets") instead of warning that it is in plain text. Dismissing a plain-text secrets file now
  lasts only until a key is added to it.

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

[Unreleased]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.2.1...HEAD
[0.2.1]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.1.0-preview.4...app-v0.2.1
[0.2.0]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.1.0-preview.4...app-v0.2.0
[0.1.0-preview.4]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.2...app-v0.1.0-preview.4
[0.1.0-preview.2]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.1...v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/hansen-consultancy/Tiresias/releases/tag/v0.1.0-preview.1
