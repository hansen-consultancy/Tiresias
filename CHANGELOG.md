# Changelog

What changed in each release of Tiresias, written for the people who use it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/). The NuGet packages are tagged `v<version>` and the
desktop app `app-v<version>`. Each release's notes on GitHub, and in the app's update dialog, are
its section below.

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.2...HEAD
[0.1.0-preview.2]: https://github.com/hansen-consultancy/Tiresias/compare/v0.1.0-preview.1...v0.1.0-preview.2
[0.1.0-preview.1]: https://github.com/hansen-consultancy/Tiresias/releases/tag/v0.1.0-preview.1
