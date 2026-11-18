# Changelog

What changed in each release of Tiresias, written for the people who use it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/). The NuGet packages are tagged `v<version>` and the
desktop app `app-v<version>`. Each release's notes on GitHub, and in the app's update dialog, are
its section below.

## [Unreleased]

### Added

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
  secret, methods, paths and Windows Hello requirement. The name stays, and programs using the
  service get the change at once.
- **How to use...** in the Services window shows again what to paste for a saved service: the
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

### Changed

- A development build no longer adds its `tir` to PATH, so it can't shadow the installed one.

### Fixed

- **Show** in the secrets editor reveals the value; it did nothing before.
- A selected row in the secrets, services and activity lists is a subtle highlight instead of dark
  blue under black text.
- The **Show** button in the secrets editor is wide enough for its text when the window opens.

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

[Unreleased]: https://github.com/hansen-consultancy/Tiresias/compare/app-v0.1.0-preview.4...HEAD
[0.1.0-preview.4]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.2...app-v0.1.0-preview.4
[0.1.0-preview.2]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.1...v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/hansen-consultancy/Tiresias/releases/tag/v0.1.0-preview.1
