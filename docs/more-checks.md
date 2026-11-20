# More checks

Status: **built**: RavenDB certificate expiry, sealed keys handed out as values, publishing keys.
**Design**: git tokens (in review), a CLI acting as the user, RavenDB clearance. Phase 6 of [guided setup](guided-setup.md) (#32). Phase 1 gave the
doctor its shape: a probe gathers facts, the pure planner in `Doctor` turns them into checks, and
a check that can go higher carries its `Now` and `Better` positions and a typed `DoctorFix`. Each
check below adds probe facts, planner cases and at most one fix type, and ships on its own.

## Rules every check keeps

- **Read names, shapes and metadata.** Where a check has to read a file holding a secret (an
  `.npmrc`, a `.pypirc`), the probe reads it and hands the planner its text, as it does a user
  secrets file today; the planner stays pure, and a check names the file, the key and the
  registry or host, never the value. A connection string is only ever parsed with
  `DbConnectionStringBuilder` and read by keyword; it is never split to print its parts.
- **No admin rights, no unlock.** The doctor never asks for Hello. A fact that needs a sealed value
  comes from metadata recorded when the value was sealed, or from the broker, and the check says
  "skipped: locked" when neither is available.
- **Only where the user pointed.** The project folders given with `--projects` (in the app, the
  secrets editor's project folders) and the user's own config files that the tools read by
  default. No crawl of the disk.
- **A finding is any check with a fix, plus any delivery with a position**
  (`DoctorCheck.IsFinding => Fix is not null || Now is not null`, as built in phase 2). Some checks
  don't move a delivery on either axis: a certificate that will expire, or one cleared for more
  than the app uses. They are findings through their fix, and carry no `Now` or `Better`. A weak
  delivery with no fix yet (a NuGet push key) is a finding through its `Now`. A check that only
  informs carries neither, and stays among the passing checks.

## RavenDB clearance and certificate expiry

**Reads.** For each RavenDB service in the vault (`RavenSetupPlanner.Recognize`): the
certificate's subject, thumbprint and expiry, and its clearance on the server.

- **Expiry.** `RavenSetup` already reads `NotAfter` when it seals the certificate. It also records
  the subject, thumbprint and expiry beside the sealed secret, as metadata outside the ciphertext
  and outside the bound policy (none of it is secret, and changing it grants nothing). A vault
  sealed before this has no metadata; the check then asks the broker, and says "skipped: locked"
  when the solo broker isn't running.
- **Clearance.** The broker asks the server who the certificate is, with that certificate
  (`GET /certificates/whoami`, which any registered certificate may call; to be confirmed against
  RavenDB 6 and 7). A new device-signed broker endpoint, `GET /raven/{service}/whoami`, returns
  the clearance and the database names it may use, and never the certificate.

**Reports.**

- expires within 30 days: Warn, "*service*'s certificate *subject* expires on *date*";
- expired: Fail, because every request through it already fails;
- `ClusterAdmin` or `Operator`: Warn, "*service*'s certificate is *clearance*: a program using it
  can change the server, not only read its data";
- `ValidUser` with access to more than one database: Warn, listing how many beyond the ones the
  app is set up for. The database names are the user's own and may be shown.

**Positions.** None. The certificate stays with the broker (E3/C1); what changes is how much it
can do and how long it keeps working.

**Fix.** `ReplaceRavenCertificate(service)`: the app opens **Edit...** on the RavenDB service,
where picking a new `.pfx` replaces the sealed certificate (`RavenSetupPlan.Replaces`). The
instruction says to have RavenDB issue a certificate limited to the app's databases, as
`ValidUser`.

**False positives.** A deliberate admin certificate kept for operations: dismissed with that
reason. Clearance is reported per thumbprint, so a new certificate is a new finding.

**Tests.** The planner gets the metadata and the whoami answer as facts: 31 and 29 days before
expiry, expired, each clearance, one database and three, no metadata and broker unreachable.

## Sealed keys handed out as values

**Reads.** The sealed environment's names and deliveries (`SealedEnvironment`: which variables
are delivered as values, which as placeholders) and the vault's https services. Never a value.

**Reports.** A variable delivered as its value, where a placeholder would do:

- its name has a base-URL partner (`SealedEnvironment.BaseUrlVariableFor`: `*_API_KEY`, `*_KEY`,
  `*_TOKEN`), and
- either the vault has an https service it could be delivered for, or its prefix is a known API
  that takes `Authorization: Bearer` and whose SDKs read the base-URL variable (OpenAI and
  OpenAI-compatible providers).

Keys known not to work this way aren't reported: Anthropic's (`x-api-key`), GitHub's (`tir exec`
is their answer, below), Azure's.

**Positions.** E4/C1 to E3/C1: the program stops holding the key.

**Fix.** `UsePlaceholder(variable, service)`, with `service` empty when none exists yet. The
instruction is `tir env placeholder add NAME service`, after `tir service add` when there is no
service. The app opens Environment variables with the variable selected and **Hand out a
placeholder instead** open.

**False positives.** A tool that ignores the base-URL variable gets nothing useful from a
placeholder. That can't be seen from outside the tool, so the finding says to try it, and
**Hand out the value** undoes it. Dismissed per variable with "this tool needs the value".

**Tests.** Prefixes known and unknown, a matching vault service, a variable already on a
placeholder, the excluded prefixes, a folder set's variable as well as a global one.

**Later.** User secrets have no placeholder reference for HTTP APIs (`tiresias:` covers `sql` and
`raven`). A `tiresias:svc/{service}` reference would extend this check to `appsettings` keys.

## Publishing keys

**Reads.** The tools' own credential files: `%APPDATA%\NuGet\NuGet.Config` and every
`NuGet.Config` under the project folders, `%USERPROFILE%\.npmrc` and project `.npmrc` files,
`%USERPROFILE%\.pypirc`.

**Reports**, per file and entry:

| Tool | Finds | Now |
|---|---|---|
| NuGet feeds | `packageSourceCredentials` with a plain `ClearTextPassword`, or `%NAME%` pointing at an unsealed variable | E5/C3 |
| NuGet push | an entry under `apikeys`. NuGet encrypts it with DPAPI for the user, which every program running as the user can undo | E5/C3 |
| npm | `_authToken=` or `_password=` with a literal, not `${NAME}` | E5/C3 |
| PyPI | a `password` in a `.pypirc` section | E5/C3 |

The check names the source, registry or repository and the file. A `_authToken=${NPM_TOKEN}`
line is reported only when `NPM_TOKEN` is an unsealed user variable, which the environment check
already finds.

**Positions and fixes.**

- **NuGet feeds:** `ImportNuGetCredentials(file)` runs `tir env nuget import` (or **Move to
  Tiresias** under **NuGet feeds**), which exists. E5/C3 to E4/C1.
- **npm and PyPI:** `SealRegistryToken(file, registry, variable)` seals the token as a variable
  (`NPM_TOKEN`, `TWINE_PASSWORD` with the username `__token__`) and takes it out of the file. For
  npm it writes `${NPM_TOKEN}` in its place, which npm expands from the environment that
  `tir run` and the terminal hook supply. E5/C3 to E4/C1. This reads the value once, to seal it;
  the finding says so before the fix runs.
- **Pushing to a public registry** (nuget.org, npmjs.org, pypi.org): the finding also names
  trusted publishing from CI as the strongest option (E1), and suggests keeping a short-lived key
  only for local pushes. Tiresias can't set that up; the fix's instruction links each registry's
  guide.
- **NuGet push keys:** no automatic fix in this phase. Tiresias could undo DPAPI, but a key used
  with `dotnet nuget push --api-key` belongs in a sealed variable passed through `tir run`, and
  that changes how the user runs the command. The instruction says that, and how to remove the
  entry.

**False positives.** A token for a private registry the user knowingly keeps in the file:
dismissed. An `.npmrc` committed with `${NAME}` placeholders is fine and not reported.

**Tests.** Each file format with a literal, a `${NAME}` reference and an empty entry; an
`apikeys` entry; malformed XML and INI read as no finding, never as a crash; registry names with
and without a scheme; no value ever in `Detail` or `Instruction`.

## Git tokens

**Reads.** `.git/config` of every repository under the project folders, `%USERPROFILE%\.gitconfig`
for `credential.helper`, and whether `%USERPROFILE%\.git-credentials` exists and how many entries
it has. Never its contents beyond the hosts.

**Reports.**

- **A token in a remote URL** (`https://user:token@host/…`): Warn, naming the repository, the
  remote and the host. The URL is printed without its user info. E5/C3: the token is in a plain
  file, and also in `git remote -v`, in logs, and in every copy of the folder.
- **The `store` helper with `.git-credentials`**: Warn, "*n* tokens in plain text for *hosts*".
  E5/C3.
- **Git Credential Manager** is reported as information, not a finding: it has no fix and is given
  no `Now`. It keeps tokens in Windows Credential Manager, which any program running as the user
  can read (E5/C3), but there is nothing better to offer until the helper below exists.

**Fix.** `RemoveTokenFromRemote(repository, remote)`: the instruction is `git -C "<repository>"
remote set-url <remote> <url without user info>`, and the token then lives wherever the user's
helper keeps it. On its own that doesn't change the position, but it stops the token spreading,
and the finding says that.

**Better, later.** A `git-credential-tiresias` helper, like the NuGet plugin: it answers git's
credential protocol from a sealed variable, after consent naming the program that ran git. That
makes every git token E4/C1, and gives this check a fix that raises the position:
`MoveGitCredentials(hosts)` imports `.git-credentials` and removes the file. For GitHub, a token
minted per run (`tir exec`) is E2/C1 and better still.

**False positives.** A local or test remote with a dummy password: dismissed per remote.

**Tests.** URLs with a user only, with a user and token, with SSH, with `insteadOf` rewrites; the
printed URL never holds the user info.

## A CLI acting as the user

Already listed in guided setup's checks, and small enough to ship here.

**Reads.** `gh auth status` and `az account show`, each tool's own status command, which reports
who is signed in but not the token. Run only when the tool is on PATH, with a short timeout.

**Reports.** `gh` signed in with a stored token: E5/C3. The Azure CLI with a cached session:
E5/C3, its refresh token as reusable as `gh`'s. Any program running as the user can act as them, unseen.

**Fix.** For `gh`, `RunThroughExec("gh")`: set up a GitHub App service and run `tir exec gh …`,
which mints a token per run after consent (E2/C1). Keep `gh`'s own sign-in only for interactive
use, or sign it out with `gh auth logout`. For `az`, no fix yet: Tiresias has no broker-held Entra
identity. It still carries its `Now` (E5/C3), so it is a finding without a fix, which says so.

**Tests.** The planner gets each tool's exit code and a parsed account summary. Signed in, signed
out, not installed, timed out.

## Later

Candidates, each its own check when it lands: `.env` files in project folders; SSH private keys
without a passphrase in `%USERPROFILE%\.ssh`; `%USERPROFILE%\.aws\credentials`; Docker's
`config.json` `auths`; the `tiresias:svc` reference above.

## Order

1. **Publishing keys**, NuGet feeds and npm first: the fix for feeds exists, and npm needs only
   `SealRegistryToken`.
2. **Sealed keys handed out as values**: facts the agent has already, and a fix that exists in the
   Environment variables window.
3. **RavenDB expiry**, with the metadata recorded at setup; then **clearance**, once `whoami` is
   confirmed against a real server.
4. **Git tokens in remote URLs**, then the `git-credential-tiresias` helper and the
   `.git-credentials` fix as their own piece of work.
5. **A CLI acting as the user**, `gh` first.

## Not in scope

- **Reading values to judge strength or validity.** No check calls a registry or a git host with a
  token to see whether it still works or what it may do.
- **Fixing on a schedule.** Checks run on the app's open, on a timer and in `tir doctor`; every fix
  is started by the user.
- **Machine-wide files.** Only the user's own config and the project folders given. A machine-level
  `NuGet.Config` under Program Files is read-only for the user and out of reach of the fixes.
