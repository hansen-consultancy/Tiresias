# CLAUDE.md

Guidance for AI agents working in this repository. Humans: [README](README.md) and
[CONTRIBUTING](CONTRIBUTING.md) say the same things at more length.

**This is a public repository.** Never commit a real secret, hostname, IP address, customer,
project or person's name — not in code, tests, docs or commit messages. Use `example.com`,
`203.0.113.x` and names like `alice`. CI's `denylist` job fails on known names but cannot know
new ones.

## Commands

```bash
dotnet build Tiresias.slnx
dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj
dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj --filter "FullyQualifiedName~GrantSelectorTests"
dotnet pack Tiresias.slnx -c Release -o artifacts
```

Needs the .NET 11 SDK plus the .NET 10 runtime. `Tiresias.Keyring` (`tir`) and `Tiresias.App` target
`net11.0-windows` (Windows Hello, TPM, DPAPI) and builds on Windows only; CI's Linux leg tests
without it. OS-specific tests use `[Platform]`, never a runtime `Assert.Ignore`.

## Layout

All projects live in `src/`; `Tiresias.slnx` is hand-written (add new projects to it by hand). `samples/` holds apps for trying Tiresias by hand (docs/testing-on-windows.md): not in the solution, never packed, built by the Windows CI leg.

| Project | Target | Role |
|---|---|---|
| `Tiresias.Core` | net10.0, packed | Vault, trust chain, grants, leases, audit |
| `Tiresias.Protocol` | net10.0, packed | Wire formats: sealed secrets envelope, agent pipe messages |
| `Tiresias.Extensions.Configuration` | net11.0, packed | `AddUserSecrets` replacement; ships the generator and `buildTransitive` props |
| `…Configuration.Generator` | netstandard2.0 | C# interceptor rerouting `AddUserSecrets` / `CreateBuilder` |
| `Tiresias.Broker`, `Tiresias.Forwarder` | net11.0 | Broker service; loopback relay identifying the calling process |
| `Tiresias.Agent` | net11.0-windows | The workstation agent's logic, shared by `tir` and the app |
| `Tiresias.Keyring` | net11.0-windows | The `tir` CLI, a thin console front over `Tiresias.Agent` |
| `Tiresias.App` | net11.0-windows, WPF | The tray app (`Tiresias.exe`): agent host, consent dialog, editor, activity, status, first run. Its pure decisions live in `Logic/`, compiled into the tests by link; every string is in `Strings.resx` |
| `Tiresias.Tests` | net11.0 | NUnit, covers all of the above |

## Seeing the app

A Debug build started with `--demo [scenario]` runs on a made-up machine filled from
`src/Tiresias.App/Demo/<scenario>.json` (default `everyday`), beside the installed app and without
touching it: every window but the recovery-key and server-setup ones can be captured, every button
acts on the made-up machine only, and Windows Hello never prompts. Use it to check a UI change by
eye or screenshot:

```bash
dotnet run --project src/Tiresias.App -- --demo
```

Need another state (fresh install, locked, many findings)? Add a scenario, with made-up names only.
New code that reads or writes the user's folders, `HKCU` or environment goes through `UserMachine`;
a new action with effects outside those (a shell command, the Recycle Bin, a network call) checks
`DemoMode.On`. While a demo runs it locks the App's Debug output: build elsewhere with
`--artifacts-path`. Details: docs/testing-on-windows.md.

## Invariants

- **Core and Protocol never reference `Tiresias.Extensions.Configuration`.** Doing so flows the
  interceptor and its build props into every Core consumer. `PackagingTests` pins this; shared
  wire types belong in Protocol.
- **Decisions are pure, I/O stays at the edges.** Grants, trust-chain verification and doctor
  checks are planners tested directly; the commands and endpoints around them are thin. Add a test
  case rather than a sentence of prose when pinning a rule.
- **Nothing is a root of trust except the pinned genesis hash.** Brokers and the Keyring verify the
  chain themselves; a control plane only relays it.
- **Secret values never reach logs, audit records, consent prompts or exceptions** — keys and
  names only.
- Wire and file formats are versioned; a format change bumps its version.

## Conventions

- Central package management: versions only in `Directory.Packages.props`, never on a
  `PackageReference`. A project uses a package only if it references it directly — don't rely on
  a transitive one.
- [Conventional Commits](https://www.conventionalcommits.org/), scopes `core`, `protocol`,
  `config`, `broker`, `forwarder`, `keyring`, `app`, plus `ci`/`build`/`docs` as types.
- Behaviour changes update `README.md` or `docs/` in the same commit.
- A change that adds or closes a threat edits its file in `docs/threats/` in the same PR: one file
  per finding, no shared header or version, summary printed by `python -I tools/threats.py`
  ([format](docs/threats/README.md)).
- User-facing changes add a line under `## [Unreleased]` in `CHANGELOG.md`, written for users, in the
  same PR. Release notes (GitHub and the app's update dialog) are that file's version sections
  (`docs/releasing.md`).
- Version is `VersionPrefix`/`VersionSuffix` in `Directory.Build.props`; releases are `v*` tags,
  published by `release.yml` via nuget.org trusted publishing.
