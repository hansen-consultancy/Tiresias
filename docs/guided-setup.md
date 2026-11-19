# Guided setup: the strongest option first

Status: **design, not built** (#32). This page designs how Tiresias steers people toward the safest way to
hold each credential, finds the weaker setups already on the machine, and keeps a growing feature
set reachable without a row of buttons per feature.

## Problem

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

1. **The strongest available option is the default, never one choice among equals.** Weaker options
   stay available, below it, each saying what it gives up.
2. **Start from what the user needs, not from the mechanism.** "An app needs a database", not
   "Set up a SQL Server".
3. **Find, then offer.** The machine is scanned for weaker setups; each finding comes with the fix
   that moves it up, one click to start.
4. **Show what is in use.** A feature appears once it applies to something on this machine; the
   rest is one step away in the catalogue, not on the home screen.
5. **Advice never costs privacy.** Detection reads names, shapes and metadata. A value is read only
   when the check can't be made otherwise, is never kept, logged or shown, and the finding says
   what was read.

## The ladder

Every credential sits on one rung. The app shows the rung and offers the next one up.

| Rung | Meaning | Examples |
|---|---|---|
| 1. No secret | The service accepts an identity instead | Windows / Entra authentication, managed identity, trusted publishing (OIDC), passkeys, Git Credential Manager |
| 2. Minted per use | A short-lived credential is created for this lease or run | Per-lease SQL logins, GitHub App installation tokens |
| 3. Never in the program | The broker uses the secret on the program's behalf | Placeholders, the broker presenting a RavenDB client certificate |
| 4. Sealed, handed out | Encrypted at rest, given to the program as its value | Sealed user secrets and environment variables, the NuGet plugin's answers |
| 5. Plaintext | Readable by anything running as the user | `.env`, `appsettings.json`, the Windows environment, a `.pfx` on disk |

Rung 4 is where most secrets enter Tiresias, and it is a fine first step: sealing is what keeps a
key out of backups, synced folders and an agent's file reads. It is not the end state where a
higher rung exists. [Need no secret at all](avoid-secrets.md) is the prose behind rung 1; the
ladder turns it into data the app and `tir` both use.

A rung belongs to a delivery, not to a secret: the same key can be rung 3 for a terminal that gets
a placeholder and rung 4 for a program that gets the value. The finding is about the weaker one.

## Findings

A **finding** is something on the machine below the rung it could be on, with the fix that raises
it. Findings come from **checks**: small, read-only probes over files and services the user
already pointed Tiresias at (user-secrets folders, project folders, sealed services), never a
crawl of the whole disk.

First checks, by what they find and what they offer:

| Check | Finds | Offers |
|---|---|---|
| Plaintext user secrets | `secrets.json` with values (already in `tir doctor`) | Seal it (rung 5 → 4), then each key's own next step |
| Secret-looking environment variables | Unsealed user variables (already in `tir doctor`) | Seal them; for an API key, placeholder delivery (→ 3) |
| Connection string with a password | `Password=`/`Pwd=` in `appsettings*.json`, user secrets or a sealed value; the key name and the server, not the password | *An app needs a database*: a `tiresias:sql/…` reference (→ 2), or Windows / Entra sign-in where the server takes it (→ 1) |
| RavenDB certificate on disk | A `.pfx`/`.pem` in a project folder, or a `Certificate` path in RavenDB configuration | *Set up a RavenDB* with that file (→ 3), then offer to delete it |
| Broad RavenDB clearance | A RavenDB service whose certificate is Cluster Admin or Operator, or has access to databases the app doesn't use (asked through the broker; the endpoint is to be confirmed) | Issue a certificate scoped to the databases the app uses, and swap it in with **Edit...** |
| Certificate expiry | A sealed certificate expiring within 30 days | Renew it before programs start failing |
| Sealed key handed out as a value | An API key whose service accepts `Authorization: Bearer`, delivered as its value | Placeholder delivery (4 → 3) |
| Publishing key | A NuGet or npm API key, sealed or plaintext | Trusted publishing in CI (→ 1); keep a short-lived key for local pushes only |
| Git token in a remote URL | `https://user:token@…` in a project's `.git/config` | Git Credential Manager (→ 1) |

A finding can be **dismissed** with a reason ("this server only takes SQL logins", "not mine").
The dismissal is kept per finding, so the same thing isn't raised again; one that comes back
changed (a new key, another server) is a new finding.

## "What do you need?"

The app's one way to add anything. It asks for the need, then lists the options for it from the
top rung down, the recommended one first with why, the others below with what they give up.

| Need | Options, strongest first |
|---|---|
| An app needs a database | SQL Server: Windows / Entra sign-in if possible; else per-lease logins. RavenDB: the broker presents the certificate |
| A program needs an API key | The service's own identity or OIDC if it has one; else a placeholder; else the sealed value |
| A command-line tool needs a key | A placeholder through `tir run` / the terminal hook; else the sealed value for that tool only |
| Protect this project's secrets | Seal its user secrets, then a finding per key that can go higher |
| Publish packages from CI | Trusted publishing; else a short-lived key sealed for local pushes |
| Sign in to git | Git Credential Manager or an SSH key in an agent; else a token sealed for the NuGet/credential plugin |

Each option starts the flow that exists today (Set up a SQL Server, Set up a RavenDB, Add a service,
Environment variables), or, for rung 1, a short guide: Tiresias holds nothing, so there is nothing
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
- The tray menu stays short: Unlock/Lock, Home, and a badge when there are new findings.

Existing windows remain the places where the work happens; this changes how people get to them.

## Architecture

- **Checks gather facts**, as `DoctorProbe` does today: read-only, no prompts. They run in the agent,
  on the app's open and on a timer, and in `tir doctor`.
- **One pure planner in Core** turns facts into findings and a need into ranked options: the
  ladder, the per-service knowledge (which upstreams accept Bearer, which servers take integrated
  sign-in) and the dismissals. Tested like `ServicePlanner`; the app, `tir doctor` and a future
  `tir advise` give the same advice because they ask the same planner.
- **A finding names its fix as a flow and its inputs** (`SetUpRaven(pfxPath)`,
  `PlaceholderFor(variable, service)`), so the app can open the window filled in and the CLI can
  print the command.

## Open questions

- **RavenDB clearance.** Which endpoint reports a certificate's own clearance and database access
  without admin rights, and on which versions? Needs checking against a real server.
- **Integrated sign-in.** Telling that a SQL Server would accept Windows or Entra sign-in for this
  app means trying it; doing that unasked is too much. Offer it as a question in the flow instead.
- **Scan scope.** Project folders the user added, user secrets and sealed services only, or also
  common places such as `%USERPROFILE%\.nuget\NuGet\NuGet.Config` and `.git/config` under those
  folders? Start with the first; each extra place is its own check.
- **Team policy.** With a remote broker, may an administrator require a minimum rung for a kind
  of secret? Out of scope until the broker has a policy model for it.

## Phases

1. **The ladder and findings in `tir doctor`**: the planner in Core, the existing checks rewritten as
   findings with rungs and fixes, plus the connection-string and certificate-on-disk checks.
2. **Findings in the app**: a findings section on Home, one-click fixes opening today's windows filled
   in, dismissals.
3. **What do you need?**: the catalogue, the ranked options, the free-text match; Add, Set up a SQL
   Server and Set up a RavenDB move behind it.
4. **Show what is in use**: the home screen keeps only the areas that apply; the rest live in the catalogue.
5. **More checks**: RavenDB clearance and expiry, sealed keys handed out as values, publishing keys,
   git tokens, each landing with its own fix.
