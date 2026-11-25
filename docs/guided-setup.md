# Guided setup: the strongest option first

Status: **phases 1 to 4 built** (#32): the axes and findings in `tir doctor`, findings in the app, *What do you need?*, and Home showing what is in use; **phase 5's first slice built**; the rest is design. This page designs how Tiresias steers people toward the safest way to
hold each credential, finds the weaker setups already on the machine, and keeps a growing feature
set reachable without a row of buttons per feature.

## Problem

- **Safe from theft is mistaken for safe.** Entra sign-in or the `gh` CLI keep no secret in a
  file, yet any program running as the user can use them silently, with no record of who or when.
- **Every way of delivering a secret looks equally finished.** A sealed environment variable handed
  to a program as its real value and a placeholder the program can't use elsewhere both end up as
  one row with a green status. The first still puts the key in the program's memory and
  environment; the second never does. Nothing tells the user the difference, or that a service may
  not need a secret at all.
- **The app protects what it is shown, and finds little on its own.** `tir doctor` notices
  unprotected `secrets.json` files and secret-looking user variables, but not a connection string
  with a password in `appsettings.json`, a `.pfx` next to a project, or a RavenDB certificate with
  cluster-wide clearance.
- **Each feature adds a button.** The Services window alone has Add, Edit, How to use, Remove, Set
  up a SQL Server and Set up a RavenDB. Someone who needs one of them has to know it exists and where.

## Principles

1. **The strongest available option is the default, never one choice among equals.** Strongest on
   both axes below: what can escape, and who may use it unseen. Weaker options stay available,
   below it, each saying what it gives up.
2. **Start from what the user needs, not from the mechanism.** "An app needs a database", not
   "Set up a SQL Server".
3. **Find, then offer.** The machine is scanned for weaker setups; each finding comes with the fix
   that moves it up, one click to start.
4. **Show what is in use.** A feature appears once it applies to something on this machine; the
   rest is one step away in the catalogue, not on the home screen.
5. **Advice never costs privacy.** Detection reads names, shapes and metadata. A value is read only
   when the check can't be made otherwise, is never kept, logged or shown, and the finding says
   what was read.

## Two axes

How safe a credential is depends on two separate things, and an option can be strong on one and
weak on the other:

- **Exposure**: what can escape, and whether it works somewhere else once it has.
- **Control**: on this device, which programs may use it, and whether anyone sees or approves
  each use.

| Exposure | Meaning | Examples |
|---|---|---|
| E1. Nothing to copy | The service accepts an identity; no reusable secret exists | Windows / Entra sign-in, managed identity, trusted publishing (OIDC), passkeys |
| E2. Short-lived | A credential is minted for this lease or run and expires with it | Per-lease SQL logins, GitHub App installation tokens |
| E3. Works only through the broker | The broker holds the secret; the program gets something useless elsewhere | Placeholders, the broker presenting a RavenDB client certificate |
| E4. Sealed, handed out | Encrypted at rest, given to the program as its value | Sealed user secrets and environment variables, the NuGet plugin's answers |
| E5. Readable | Anything running as the user can read it | `.env`, `appsettings.json`, the Windows environment, a `.pfx` on disk, a token in Windows Credential Manager |

| Control | Meaning | Examples |
|---|---|---|
| C1. Approved | Use needs the user's consent, naming the program; every use is recorded | Tiresias leases, consent per program, the activity log |
| C2. Recorded | Every use is recorded with program and time, but nothing asks | A brokered service a program may use without asking (planned) |
| C3. Silent | Any program running as the user can use it, and nothing records it | The `gh` CLI's token, an Entra session in the Azure CLI, Git Credential Manager, a sealed value once handed out |

**Exposure without control isn't enough.** Entra sign-in is E1: there is no password to steal or
replay from another PC. It is also C3: any program running as the user can ask for a token and act
as them, unseen. The `gh` CLI is worse on both: its token is E5 for any process running as the user
and C3 every time it is used. Protecting against a credential leaving the device is not protecting
against something on the device using it. Tiresias exists for the second: it decides which program
may use a credential, asks first, and records each use.

So the recommended option is the one strongest on both axes, which usually means **through the
broker**: E2 or E3 with C1. Where the axes pull apart (E1/C3 against E3/C1), the options say so
and the user picks; the default leans to control, because that is the risk the user can't see.
Identities can be brought under control too: the broker mints the short-lived token (a GitHub App
token for `gh` through `tir exec` today; an Entra token from a broker-held identity later) only
after consent, so even E1 gets C1.

**The limits stay stated.** Consent stops silent use; it doesn't stop a malicious program from
asking and hoping the user clicks Allow (the dialog names the program, and **This wasn't me**
blocks it), and a value handed out at E4 is the program's to misuse once it has it. Neither axis
protects against code running as administrator.

Most secrets enter Tiresias at E4/C1, and that is a fine first step: sealing keeps a key out of
backups, synced folders and an agent's file reads. It is not the end state where a better option
exists. [Need no secret at all](avoid-secrets.md) is the prose behind E1; the axes turn it into data
the app and `tir` both use.

A position belongs to a delivery, not to a secret: the same key can be E3 for a terminal that gets
a placeholder and E4 for a program that gets the value. The finding is about the weaker one.

## Findings

A **finding** is something the user can act on: any check with a fix, and any delivery weaker, on
either axis, than it could be (a delivery finding says where it sits and where its fix takes it,
even when the app has no fix for it yet, like a certificate file that isn't RavenDB's). Findings come from **checks**: small, read-only probes over files and services the user
already pointed Tiresias at (user-secrets folders, project folders, sealed services), never a
crawl of the whole disk.

First checks, by what they find and what they offer:

| Check | Finds | Offers |
|---|---|---|
| Plaintext user secrets | `secrets.json` with values (already in `tir doctor`) | Seal it (E5 → E4), then each key's own next step |
| Secret-looking environment variables | Unsealed user variables (already in `tir doctor`) | Seal them; for an API key, placeholder delivery (→ E3/C1) |
| Connection string with a password | `Password=`/`Pwd=` in `appsettings*.json`, user secrets or a sealed value; the key name and the server, not the password | *An app needs a database*: a `tiresias:sql/…` reference (→ E2/C1), or Windows / Entra sign-in where the server takes it (→ E1) |
| RavenDB certificate on disk | A `.pfx`/`.pem` in a project folder, or a `Certificate` path in RavenDB configuration | *Set up a RavenDB* with that file (→ E3/C1), then offer to delete it |
| Broad RavenDB clearance | Built: a RavenDB service whose certificate is Cluster Admin or Operator, a ValidUser for more than one database, or Admin on its database (asked through the broker, which calls RavenDB's `/certificates/whoami` with the certificate) | Issue a certificate scoped to the databases the app uses, and swap it in with **Edit...** |
| Certificate expiry | Built: a RavenDB service's certificate expiring within 30 days, or expired, from the subject, thumbprint and expiry recorded at setup (`raven-certificates.json`, beside the vault) | **Edit...** on the service with a new `.pfx` |
| Sealed key handed out as a value | Built: a global sealed variable delivered as its value whose name has a base-URL partner (`*_API_KEY`, `*_KEY`, `*_TOKEN`), for a vault https service or a known Bearer API (OpenAI and compatible); not Anthropic, Azure or GitHub keys. Needs Tiresias unlocked, so `tir doctor` skips it | Placeholder delivery (E4 → E3): Environment variables with the key checked, or `tir env placeholder add` |
| Publishing key | Built: a NuGet feed token in plain text or in a user variable, a NuGet push key under `apikeys`, an npm `_authToken`/`_password`/`_auth` in plain text, a `.pypirc` password; the entry, registry and file, never the value | Feeds: `tir env nuget import` (E5 → E4/C1). npm, PyPI's `pypi`: `tir env import` seals it and leaves `${NAME}` (E5 → E4/C1). Push keys: a sealed variable through `tir run`. For the public registries, trusted publishing in CI (→ E1) |
| Git token in a remote URL | Built: `https://user:token@…` in a remote's `url`/`pushurl` or a `[url]` rewrite in a project's `.git/config`, printed without the user info; entries in `~/.git-credentials`, by host | `git remote set-url` without the user info, which stops it spreading (still E5/C3); later, a `git-credential-tiresias` helper (→ E4/C1) |
| A CLI acting as the user, unseen | Built: `gh` signed in with a stored token, the Azure CLI with a cached Entra session (from each tool's own config file, offline, never the token) | Run it through `tir exec` with a token minted per run after consent (C3 → C1); keep the tool's own sign-in only for interactive use, or sign it out |

A finding can be **dismissed** with a reason ("this server only takes SQL logins", "not mine").
The dismissal is kept per finding, so the same thing isn't raised again; one that comes back
changed (a new key, another server) is a new finding.

A check that can raise the same finding many times names its **kind** ("projects that set
`<UserSecretsId>` but don't reference the package"). The findings of one kind show as one line with
their count, ahead of single findings only when they fail; the line opens to its members, each with
its own fix, and **Dismiss all** sets them aside with one reason. A drive of repositories raises
hundreds of findings, mostly copies in worktrees; one line per kind keeps them readable.

## "What do you need?"

The app's one way to add anything. It asks for the need, then lists the options for it strongest
first on both axes, the recommended one first with why, the others below with what they give up.

| Need | Options, strongest first |
|---|---|
| An app needs a database | SQL Server: Windows / Entra sign-in if possible; else per-lease logins. RavenDB: the broker presents the certificate |
| A program needs an API key | The service's own identity or OIDC if it has one; else a placeholder; else the sealed value |
| A command-line tool needs a key | A placeholder through `tir run` / the terminal hook; else the sealed value for that tool only |
| A CLI that signs in as me (`gh`, `az`) | A token minted per run through `tir exec`, after consent; else the tool's own sign-in, which works silently for any program |
| Protect this project's secrets | Seal its user secrets, then a finding per key that can go higher |
| Publish packages from CI | Trusted publishing; else a short-lived key sealed for local pushes |
| Sign in to git | Git Credential Manager or an SSH key in an agent; else a token sealed for the NuGet/credential plugin |

Each option starts the flow that exists today (Set up a SQL Server, Set up a RavenDB, Add a service,
Environment variables), or, for an E1 option, a short guide: Tiresias holds nothing, so there is nothing
to set up in the app, only steps to follow elsewhere.

A free-text box at the top matches what the user types against the needs and known services ("my
EF Core app talks to Azure SQL", "OpenAI key for a script"). A plain keyword and synonym match is
enough at first; nothing typed there leaves the machine.

## The app's shape

- **Home** (today's Status window): lock state, the findings with their one-click fixes, and
  **Add...** opening *What do you need?*.
- **What is in use**: the areas that apply to this machine, e.g. Services once a service exists,
  Environment variables once one is sealed. An area with nothing in it isn't on the home screen;
  it is reached through *What do you need?*.
- The tray menu stays short: Unlock/Lock, Home, and a badge when there are new findings (built: a
  dot on the icon, from checks the app runs in the background; [as built](what-do-you-need.md#as-built)).

Existing windows remain the places where the work happens; this changes how people get to them.

## Architecture

- **Checks gather facts**, as `DoctorProbe` does today: read-only, no prompts. They run in the agent,
  on the app's open and on a timer, and in `tir doctor`.
- **One pure planner in Core** turns facts into findings and a need into ranked options: the
  two axes, the per-service knowledge (which upstreams accept Bearer, which servers take integrated
  sign-in) and the dismissals. Tested like `ServicePlanner`; the app, `tir doctor` and a future
  `tir advise` give the same advice because they ask the same planner.
- **A finding names its fix as a flow and its inputs** (`SetUpRaven(pfxPath)`,
  `PlaceholderFor(variable, service)`), so the app can open the window filled in and the CLI can
  print the command.

## Open questions

- **Integrated sign-in.** Telling that a SQL Server would accept Windows or Entra sign-in for this
  app means trying it; doing that unasked is too much. Offer it as a question in the flow instead.
- **Scan scope.** Project folders the user added, user secrets and sealed services only, or also
  common places such as `%USERPROFILE%\.nuget\NuGet\NuGet.Config` and `.git/config` under those
  folders? Start with the first; each extra place is its own check.
- **Team policy.** With a remote broker, may an administrator require a minimum position for a kind
  of secret? Out of scope until the broker has a policy model for it.

## Phases

1. **Built. The axes and findings in `tir doctor`**: the planner in Core, the existing checks rewritten as
   findings with positions and fixes, plus the connection-string and certificate-on-disk checks.
2. **Built. Findings in the app**: a findings section on Home, one-click fixes opening today's windows filled
   in, dismissals. The app checks the project folders the secrets editor scans. A dismissal is keyed
   by the line, its fix's inputs, its position and, for a secrets file, its key names, hashed
   (`Dismissals.KeyOf`), so a changed finding comes back; `dismissals.json` beside the keyring is shared with `tir doctor`.
3. **Built. What do you need?**: the catalogue, the ranked options, the free-text match; Add, Set up a SQL
   Server and Set up a RavenDB move behind it ([design](what-do-you-need.md)). `tir advise` prints the same list.
4. **Built. Show what is in use**: the home screen keeps only the areas that apply; the rest live in the catalogue
   ([design](what-do-you-need.md#phase-4-what-is-in-use)).
5. **Built, first slice. Attack surface**: installed software and extensions as findings, ranked
   by what uses credentials ([attack surface](attack-surface.md)). Offline only: it reads the
   extension metadata of VS Code, VS Code Insiders, Cursor and Windsurf, the user and machine Run
   keys and the Startup folder (with an offline Authenticode check of each program; Windows' and
   Store apps' own files count as unchecked), the blocklist, and which program got which credential
   in the last 90 days from the activity and audit logs. It raises three kinds of findings, none
   with a position: an extension with an unknown publisher or unchanged for two years inside a
   program that used a credential (**Remove...** runs the host's `--uninstall-extension` after
   approval), an unsigned program that starts at log-on, and a blocked program still on the PC
   (both **Show file**). A program that starts at log-on but that the user hasn't opened in 90
   days (UserAssist; unknown for a program with a tray icon) gets **Turn off at log-on...**, the
   same switch as Task Manager's. Uninstall entries are checked against the disk: an entry for
   software that is gone and an older version's stale duplicate (**Remove entry...** saves it to a
   `.reg` file first), and a program whose uninstaller is missing (reinstall it over itself). A
   program the user hasn't opened in 90 days (nothing in its folder in UserAssist; unknown when it
   runs unseen) is listed last, all of them as one line, without counting for the badge; its
   **Show installed programs** opens the **Installed** page: every installed program with its last
   opening, why its use is unknown where it is, and the credentials it used, unused first. A
   finding's reasons are in its name, so a dismissal survives a version
   update and a new reason brings it back. Still design: the opt-in trust lookups (OSV,
   deps.dev, marketplaces, winget-pkgs) and the vulnerability and unverified-publisher findings
   they raise; **Update** and `winget`/`dotnet tool`/`npm` uninstalls (browser, unpacked,
   Visual Studio, JetBrains and Notepad++ extensions are read, #107); trusting a publisher;
   separate
   *How credentials are held* and *What can reach them* groups. The global tools are listed
   once a day, not per run, and on a managed PC only what the user installed is judged (#107). `tir doctor --surface` lists the inventory (extensions with their host's
   reach, global tools, log-on entries with signature and last use).
6. **Built. More checks**: RavenDB certificate expiry and clearance, sealed keys handed
   out as values, publishing keys, git tokens and a CLI acting as the user (`gh`, `az`), each with
   its own fix where one exists ([more checks](more-checks.md)).
