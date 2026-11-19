# Attack surface: less software, less to trust

Status: **design, not built** (#34). Part of [guided setup](guided-setup.md): its checks produce findings
in the same model, with the same dismissals and one-click fixes.

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

## Findings and fixes

| Finding | Offers |
|---|---|
| Not used in N months (90 by default) | Uninstall: the exact `winget uninstall --id …`, `dotnet tool uninstall -g …`, `npm rm -g …` or `code --uninstall-extension …`, shown and run only on approval |
| Extension or plugin inside a program that uses credentials, from an unverified or unknown publisher | Review it, disable or remove it; or move the credential's use out of that program (a placeholder through `tir exec` instead of the editor's own sign-in) |
| Known vulnerability in the installed version | Update to the fixed version, or remove it |
| Unsigned binary on `PATH` or in startup | Show where it came from; remove it if no one recognises it |
| Runs at startup but rarely used | Turn the startup entry off, keep the program |

Uninstalling needs the user's approval every time and admin rights for machine-wide software; it
never happens from a scan. Dismissals work as in guided setup: "I use this monthly" stops the
finding until something about it changes.

## Isolation

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
- **Thresholds.** How long unused is "unused" per kind (a yearly tax tool versus a browser
  extension)? Start with 90 days and a per-finding dismissal.
- **Scope.** Machine-wide software belongs to an administrator on a managed PC. Report it, but
  suggest removal only for what the user installed.

## Phases

1. **Inventory**: applications, extensions and global tools, with last use where known, as
   `tir doctor` facts; no online lookups.
2. **Cross with credentials**: rank by what each host program has asked Tiresias for; findings in
   the app.
3. **Trust lookups** (opt-in): deps.dev, OSV, marketplaces, winget-pkgs, Authenticode.
4. **Fixes**: approved uninstalls and startup changes through winget and each tool's own command.
5. **Isolation**: placeholder environments for containers and WSL, and the finding that suggests them.
