# Package managers: the safeguards they have on

Status: **built**. Part of the [attack surface](attack-surface.md) checks: a package installed
today is code that runs as the user, with the same reach to credentials as any program.

## The problem

Most malicious packages are caught within days of publication, and most do their harm the
moment they are installed, through an install script. Package managers added two safeguards for
this: **not running dependencies' install scripts** unless a project allows them, and **a
minimum release age**, so a release is installed only once it has been public long enough to be
noticed. Whether either is on depends on the tool, its version and a user-level setting nobody
remembers setting. A developer's PC has five or six of these tools.

## What is checked

`Doctor.SupplyChain` judges each toolchain the probe found. Lines name the tool, its version and
the setting, never a file path, a feed or a registry. A version is read from a file the tool
installs beside itself (`node_modules\npm\package.json`, the SDK folder, pip's `dist-info`, uv's
`uv-receipt.json`, Go's `VERSION`); no tool is started. npm, pnpm and Yarn are found by any of their shims on `PATH`
(`.cmd`, `.exe`, `.ps1` or the extensionless script). When the version is unknown, the line says
so and the setting alone decides.

| Tool | Install scripts | Release age | Also |
|---|---|---|---|
| npm | Off by default from 12 (a project's `allowScripts` names those that run); before 12, only with `ignore-scripts` | `min-release-age` (days, 11.10+), or `before` | |
| pnpm | Off by default from 10 (`allowBuilds`); on again with `dangerouslyAllowAllBuilds` | `minimumReleaseAge` (minutes, 10.16+); a day by default from 11 | |
| Yarn 2+ | Off by default from 4.14; `enableScripts` | `npmMinimalAgeGate` (minutes, or `7d`); a day by default from 4.15 | Yarn 1 has neither |
| Bun | Only for packages a project trusts, or on Bun's own list of popular ones; `install.ignoreScripts` | `install.minimumReleaseAge` (seconds) | |
| NuGet | None; a package's build targets run on build, and nothing stops that | `minPublishAgeHours` per source (.NET 11 SDK); gates add and update, not restoring a pinned version | `signatureValidationMode` `require` |
| pip | Builds code from a source package; `only-binary = :all:` stops it | `uploaded-prior-to` (26.0; `P7D` from 26.1) | |
| uv | As pip; `no-build` | `exclude-newer` (a duration from 0.9.17) | |
| Go | None | None | `GOSUMDB=off` turns checksum checks off |
| Cargo | `build.rs` runs on build; nothing stops it | `registry.global-min-publish-age` (1.100) | |
| Gradle | | | `org.gradle.dependency.verification` set to `off` or `lenient` in the user's `gradle.properties` weakens every project's verification |

Where each reads its settings, lowest precedence first; an environment variable wins over every file:

| Tool | Files | Variables |
|---|---|---|
| npm | `<prefix>\etc\npmrc`, `~\.npmrc` | `npm_config_*` |
| pnpm 10 | `~\.npmrc`, `%LOCALAPPDATA%\pnpm\config\rc` | `npm_config_*` |
| pnpm 11+ | `%LOCALAPPDATA%\pnpm\config\config.yaml` only | `pnpm_config_*` |
| Yarn | `~\.yarnrc.yml` | `YARN_*` |
| Bun | `~\.bunfig.toml`, `%APPDATA%\.bunfig.toml` | |
| NuGet | `%APPDATA%\NuGet\NuGet.Config` | |
| pip | `~\pip\pip.ini`, `%APPDATA%\pip\pip.ini`; `[install]` before `[global]` | `PIP_*` |
| uv | `%APPDATA%\uv\uv.toml` | `UV_*` |
| Go | `%APPDATA%\go\env` | `GOSUMDB` |
| Cargo | `~\.cargo\config`, `~\.cargo\config.toml` | `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE` |
| Gradle | `~\.gradle\gradle.properties` | |

Only a fixed list of setting variables is read (`Doctor.ToolchainVariables`), so no credential
variable is ever opened. A project's own `.npmrc`, `pnpm-workspace.yaml`, `bunfig.toml` or
`NuGet.Config` can still turn a safeguard on or off for that project; the lines say what the
machine's default is.

## Findings

| Line | Status | Fix |
|---|---|---|
| Install scripts run for every dependency | Warn | Update to the version that turns them off, or the tool's own setting |
| No minimum release age | Warn | The tool's command for a week: `npm config set min-release-age 7`, `pnpm config set minimumReleaseAge 10080`, `yarn config set -H npmMinimalAgeGate 7d`, `dotnet nuget update source nuget.org --min-publish-age-hours 168`, `pip config set global.uploaded-prior-to P7D`, or the line to add for Bun, uv and Cargo. On a version without the setting, the update comes first |
| Builds from source (pip, uv), unsigned packages accepted (NuGet) | Ok, with a fix | A suggestion: it can break a working setup, so it sorts last and doesn't count for the tray badge |
| A release age set on a version older than the setting (npm before 11.10, pnpm before 10.16, Bun before 1.3, NuGet before the .NET 11 SDK, pip before 26.0 or a duration before 26.1, a uv duration before 0.9.17, Cargo before 1.100) | Warn | The update; the setting then applies. Not for Yarn: a project picks its own Yarn, so the one on `PATH` says little |
| Go checksums off, Gradle verification weakened | Warn | Remove the setting |

The fix is `ChangeToolSetting`: the app's **Copy** copies it, `tir doctor` prints it. Warnings of
one kind group on Home ("3 package managers that install a release the minute it is published").
Every line is a developer line (`ForDevelopers`) and under **What can reach them** (`Surface`).

A week is suggested because most malicious releases are found and pulled within days; a security
fix is still a week late, which is why npm, pnpm, Yarn, Bun and NuGet all let a package be
excluded from the age.

## Not checked

- **Maven**: checksum policy is set per repository, and Maven has no minimum age or signature
  check of its own.
- **pipx** runs pip, so pip's settings are what it uses.
- **Deno, Poetry and Bundler** have release ages too; they are left until someone asks.
- **Audits** (`npm audit`, NuGet's audit) are on by default and report after the fact; turning
  them off is rare enough not to check.

## Threats

Nothing new is trusted or exposed: the probe reads the tools' own settings files and a version
file, starts nothing, and reports settings, never a credential or a path. No threat entry.
