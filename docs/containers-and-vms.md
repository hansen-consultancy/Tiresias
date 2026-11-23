# Containers, WSL and VMs: what your account can reach

Status: **phases 1 to 5 built, phase 6 partly built** (account facts: engine pipes, WSL disks, Hyper-V; devcontainer files and forwarding; Docker engine, WSL and Hyper-V file contents, opt-in); the rest is design. Tracks issue #113. This page designs a doctor check, **Reachable
from your account**, that tells you which secrets a normal program running as you could read inside
your containers, WSL distributions and Hyper-V VMs. It extends the [attack surface](attack-surface.md)
work (#34) and follows the rules of [more checks](more-checks.md#rules-every-check-keeps).

## The problem

"Run it in a container" protects the host from what runs *inside*. It does not protect what is
inside from the host. A devcontainer started from VS Code holds its tokens in its environment; a
WSL distribution keeps `~/.aws/credentials` and shell history in a disk image in your profile; a
Hyper-V guest's memory sits in a checkpoint file. Each one is often an easier path to a secret than
the host's own files, because nothing seals it and nobody looks there.

Tiresias already asks "which program can reach which credential" on the host. This check asks the
same of the environments the host runs, from the side of any program running as you, without admin
rights.

## Decisions

- **Names only.** The check reports environment variable names, file paths and counts. It never
  shows, logs or stores a value, and reads a value into memory only where the source hands it over
  with the name (the engine's JSON, a `.env` line), in a buffer it clears before returning.
- **Account facts by default, contents by opt-in.** Whether your account *can* reach an engine, a
  distribution or a VM is a fact about your account, read on every doctor run. Looking *inside*
  (asking the Docker engine about containers, reading a running distribution's files) touches data
  you never gave Tiresias, so it runs only when you start it.
- **Never start, mount, elevate or open.** The check doesn't start a stopped WSL distribution or
  container, never mounts or opens a disk image or checkpoint, and never asks for an administrator.
  For Hyper-V it reports that a guest *could* be read, and by which path.
- **Only commands that exist.** Every fix names `tir run`, `tir env`, `tir exec`, a VS Code setting
  or a Windows command that works today. Placeholders from inside a container don't work yet (the
  forwarder listens on the host's loopback only), so no fix offers them; *Later* sketches how.
- **One line per environment on Home.** Many findings of one kind collapse into one line, as
  [app design](app-design.md) rule 3 asks.

## What a program running as you can reach

The exact condition for each environment, from a process with your normal (UAC-filtered) token.
"Reachable" means that process can read it now, without a prompt.

| Environment | Reachable when | What it then reads |
|---|---|---|
| **Docker engine** (Docker Desktop, Linux or Windows containers; Docker CE; Rancher Desktop) | The engine's named pipe exists (the engine is running) **and** its DACL grants your token read/write. Docker Desktop grants `docker-users` and, in practice, the installing user directly; a Docker CE `docker_engine` pipe grants Administrators unless `daemon.json` sets `"group"` | Every container's and image's environment (`GET /containers/{id}/json`, `GET /images/{id}/json`: `Config.Env` as `NAME=value`), running or stopped; `docker exec` into any running one; the host folders each mounts |
| **Devcontainer files** | Always: `devcontainer.json` and the `.env` files it names live in your project folders, owned by you | `containerEnv`, `remoteEnv`, `runArgs` (`-e`, `--env-file`), `mounts`, Compose `env_file` |
| **Devcontainer forwarding** | VS Code's Dev Containers extension is installed, and a container it started is running | Through the container: your host git credentials (credential helper forwarding), your Docker registry logins (`dev.containers.dockerCredentialHelper`), keys loaded in the host's SSH agent. This is the reverse path: anything inside the container can ask the host |
| **WSL distribution, running** | The distribution is running: `\\wsl.localhost\<distro>` serves its files as the distribution's default user | That user's home: `~/.ssh`, `~/.aws`, `~/.kube`, `~/.docker/config.json`, `.env` files, shell history. Everything when the default user is `root` |
| **WSL distribution, stopped** | Its `ext4.vhdx` (the `BasePath` in `HKCU\…\Lxss\{guid}`) is in your profile and owned by you | The whole file system, copied and parsed offline by any user-mode ext4 reader. No admin, no mount |
| **Hyper-V guest** | Your token has **Hyper-V Administrators** (`S-1-5-32-578`) enabled. UAC does not filter this group, unlike Administrators | Every VM: export it, checkpoint it, attach its disk elsewhere. Checkpoint and saved-state files (`.vmrs`, `.vmgs`, `.bin`) hold guest memory |
| **Hyper-V disk files, without the group** | A VM's `.vhdx`, `.avhdx` or saved-state file has a DACL that grants your token `FILE_READ_DATA` (a VM created under your own folders often does) | That disk or that memory image, offline |
| **Hyper-V, as an administrator** | Administrators is deny-only in your normal token | Not reachable without a UAC prompt. Reported as *an administrator prompt away*, not as reachable |

Two things this table makes plain, which the findings say in words:

- **The Docker engine pipe is root over every container**, and with the Windows-containers engine
  (which runs as `SYSTEM`) a bind mount of `C:\` is administrator on the host. With the Linux
  engine it is root in the Docker VM and your own files through file sharing. Either way, any
  program you run can do it while the engine runs.
- **A stopped container or distribution still holds its secrets.** A stopped container keeps its
  environment until it is removed; a stopped distribution's disk is a file you own.

## Discovery

All read-only. The left column runs on every doctor run; the right only after opt-in (*Consent*).

| Environment | Account facts (default) | Contents (opt-in) |
|---|---|---|
| Docker engine | Which engine pipes exist (`\\.\pipe\docker_engine`, `dockerDesktopLinuxEngine`, `dockerDesktopWindowsEngine`), and whether each one's DACL grants your token, by `AccessCheck` on its security descriptor (read with `READ_CONTROL` only, no connection) | `GET /_ping`, then `/containers/json?all=1`, `/containers/{id}/json`, `/images/json` and `/images/{id}/json`, each with a 10-second timeout. Env names, mount sources, the `devcontainer.local_folder` label. Nothing that writes, execs or pulls |
| Devcontainers | none | `.devcontainer.json`, `.devcontainer/devcontainer.json` and `.devcontainer/*/devcontainer.json` under the project folders (`--projects`, or the secrets editor's folders), the `.env` and Compose files they name, and VS Code's user `settings.json` for the three forwarding settings. Folders from running containers' `devcontainer.local_folder` labels are added |
| WSL | Distributions from `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` (name, version, `BasePath`), and whether each `ext4.vhdx` is owned by or readable for you (security descriptor only) | For **running** distributions only (`wsl.exe --list --running --quiet`, which starts nothing): known credential paths under each home in `\\wsl.localhost\<distro>\home\*` and `\root`, by name and existence. `docker-desktop*` distributions are skipped: the engine row covers them |
| Hyper-V | Whether `S-1-5-32-578` is in your token and enabled, and whether Administrators is deny-only | Members only: VM names and their disk, checkpoint and saved-state paths from WMI (`root\virtualization\v2`, read-only queries). Everyone: the DACLs of disk files under the default folders (`%PUBLIC%\Documents\Hyper-V\Virtual Hard Disks`, `%ProgramData%\Microsoft\Windows\Hyper-V`) and the VM paths found, by `AccessCheck` |

Accessing `\\wsl.localhost\<distro>` **starts** a stopped distribution. That is why contents are read
only from running ones, and the stopped ones are reported through their disk file.

## Names only: what is read, and what counts as secret-looking

Three kinds of read, from least to most:

1. **Existence only.** A path is checked with `File.Exists` or its directory listed; the file is
   never opened. Used for private keys, shell history, `~/.kube/config`, cloud CLI folders and
   Hyper-V files.
2. **Names from a stream.** A `NameScan` in `Tiresias.Core` reads a format from a pooled byte buffer
   and returns names only, then clears the buffer (`CryptographicOperations.ZeroMemory`). It never
   creates a `string` from a value. Formats: `NAME=value` lines (`.env`, `--env-file`, the engine's
   `Config.Env` entries), INI section and key names (`~/.aws/credentials`, `.npmrc`, `.pypirc`),
   and JSON property names (`devcontainer.json`'s `containerEnv`/`remoteEnv`, `~/.docker/config.json`'s
   `auths` hosts) read with `Utf8JsonReader`, skipping each value without decoding it.
3. **Two facts about a value**, computed from the span and dropped: whether it is empty, and
   whether it starts like a reference (`${localEnv:`, `${env:`, `${`, `%`) or a path. A value that
   is a reference to the host environment is not a secret on disk and is not reported.

The Docker engine sends `Config.Env` with values: there is no names-only endpoint. The probe reads
each response with `Utf8JsonReader` over a pooled buffer, keeps the part of each entry before the
first `=`, and clears the buffer. That is the least the API allows, and the reason the engine is
opt-in.

**Secret-looking names** use the rule the host's environment check already uses
(`SealedVariables.LooksSecret`: `KEY`, `TOKEN`, `SECRET`, `PASSWORD`/`PASSWD`/`PWD`, `CREDENTIAL`,
`CONNECTION_STRING`, never the Windows-set names), plus, for containers and distributions:

- names that are credentials without saying so: `*_URL`, `*_URI` and `*_DSN` (`DATABASE_URL`,
  `REDIS_URL`, `MONGO_URI`) whose value has user info (`scheme://user:…@`; only that fact is
  kept), and `*_PAT`, `*_AUTH`, `*_ACCESS_KEY_ID`;
- known credential **files**, by path: `~/.ssh/id_*` without `.pub`, `~/.aws/credentials`,
  `~/.azure/`, `~/.config/gcloud/`, `~/.kube/config`, `~/.docker/config.json` with `auths`,
  `~/.git-credentials`, `~/.netrc`, `~/.npmrc` and `~/.pypirc` with a token line,
  `~/.config/gh/hosts.yml`, `~/.bash_history` and `~/.zsh_history` (reported as "may hold
  commands with tokens", never searched);
- **mounts** of host credential folders into a container: a mount source under `%USERPROFILE%\.ssh`,
  `.aws`, `.azure`, `.kube`, `.docker`, `.config\gh` or the Tiresias keyring folder.

Excluded, so the list stays short: names the image's base sets (`PATH`, `HOME`, `LANG`,
`*_VERSION`), the Tiresias decoys (`IsDecoyVariable`), and anything the user dismissed.

## Consent

**Recommended default: account facts on, contents off until you start it.**

- Account facts (group membership, pipe and file DACLs, the distribution list) are about your own
  account and read no one's data. They run with every `tir doctor` and every check on Home, so
  "the Docker engine is open to every program you run" shows without asking.
- Contents are opt-in, per run or as a standing choice:
  - `tir doctor --reach` looks inside once. Typing the flag is the consent.
  - Home shows one card while it has never been run: **See what your containers, WSL and VMs
    expose**, with **Check now**. After a check, the card turns into the findings and a **Check
    daily** switch, off by default.
  - The choice is a plain app setting (`reachScan: off | once | daily`). It widens what Tiresias
    *reads* on this machine, not what leaves it, so it needs no Windows Hello. Nothing from this
    check ever reaches an alert payload beyond `findings.new` and a count ([alerts](alerts.md)).

Why not on by default: asking the Docker engine pulls other programs' values into Tiresias's memory,
however briefly, and talks to another product's API. A credential broker that quietly reads every
container's environment is the thing it warns about. The account facts already say whether there is
anything to worry about; the contents say exactly what, when the user wants to know.

## Findings

Each is a `DoctorCheck` with a `Kind`, so one kind is one line on Home with its members behind
**Details**. A finding names the environment, the location and the names; never a value.

| Finding | Raised when | Position | Fix |
|---|---|---|---|
| Docker engine open to every program you run | A pipe exists and grants your token | none | `ReachGuide("Docker engine")`: quit Docker Desktop when you don't use it (the pipe goes with it); if you don't use Docker, leave the group with `Remove-LocalGroupMember -Group docker-users -Member <you>`, which needs an administrator, so it is printed, not run |
| Secrets in a container's environment | A container (running or stopped) or image has secret-looking env names | E5/C3 → E4/C1 | `InjectAtRunTime(container)`: for a devcontainer, move the name from `containerEnv` to `remoteEnv` as `"${localEnv:NAME}"`, seal it with `tir env set NAME --folder <project>`, and start VS Code with `tir run -- code <project>`. `remoteEnv` isn't in the container's config, so the engine no longer shows it. Otherwise `tir run --only NAME -- docker run -e NAME …`, which keeps it off disk and out of the image. Then `docker stop` and `docker rm` the old container |
| Secret baked into an image | An image's `Config.Env` has a secret-looking name | E5/C3 | The same, plus rebuild without the `ENV` line; a value in an image layer outlives every container |
| Host credential folder mounted into a container | A mount source is one of the folders above | none | `ReachGuide("Container mounts")`: remove the mount from `devcontainer.json`'s `mounts` or `runArgs` |
| Secrets in a devcontainer file | `containerEnv`, `remoteEnv` or a named `.env` holds a secret-looking name with a literal value | E5/C3 → E4/C1 | `InjectAtRunTime(folder)`, as above: the file keeps `${localEnv:NAME}` |
| Credential forwarding you may not use | Dev Containers is installed and `dev.containers.gitCredentialHelperConfigLocation` isn't `none`, or `dev.containers.dockerCredentialHelper` isn't `false`; or the host `ssh-agent` service is running with keys | none | `ReachGuide("Devcontainer forwarding")`: set the setting in VS Code user settings, or stop the agent (`Stop-Service ssh-agent`, which a user can't always do; then remove keys with `ssh-add -D`) |
| Secrets in a running WSL distribution | A known credential file exists, or a `.env` has secret-looking names | E5/C3 → E4/C1 | `ReachGuide("WSL")`: seal it on Windows with `tir env set NAME`, and pass it in for one command with `tir run --only NAME -- wsl -d <distro> <command>`, adding `NAME` to `WSLENV` (`WSLENV=NAME/u`) so WSL forwards it. Delete the file afterwards |
| WSL disk readable offline | A distribution's `ext4.vhdx` is owned by or readable for you, and it is stopped or its contents weren't checked | none | None: Windows gives the owner this file. So it is a passing check that informs, not a finding: it says the distribution's secrets are as exposed while it is stopped, and points at the row above |
| Hyper-V guests readable | `S-1-5-32-578` is enabled in your token | none | `ReachGuide("Hyper-V")`: leave Hyper-V Administrators if you don't manage VMs (needs an administrator); inside the guest, turn on BitLocker with a virtual TPM so its disk and checkpoints are ciphertext to the host |
| Hyper-V file readable without the group | A disk, checkpoint or saved-state file's DACL grants your token read | none | `ReachGuide("Hyper-V")`: move the VM's files to a folder only administrators read, or remove your account's entry from the file's ACL |

The positions follow [guided setup](guided-setup.md)'s axes: a value in a container environment or
a distribution's file is readable by any program and used silently (E5/C3); sealed and handed over
by `tir run` after consent it is E4/C1. Findings without a position are findings through their fix,
like surface findings.

Two new fix types. `InjectAtRunTime(where, names)`: its instruction is the exact `tir env set` and
`tir run` lines for the names found, which the app copies. `ReachGuide(topic)`: steps outside
Tiresias, linking this page's *Findings*; not `FollowGuide`, which means "no secret needed" (E1).

**Ranking.** Inside **How credentials are held**, these sit with the host's own plaintext findings.
Inside **What can reach them**, the account-level findings rank by what they open: Hyper-V and the
Windows-containers engine (host administrator) first, then the Linux engine, then forwarding.

## Where it shows up

**`tir doctor`** prints the account facts as checks, like every other check:

```text
WARN  docker engine: docker_engine is open to docker-users and your account, so every program you run can, while Docker runs, read every container's environment, …
      fix: quit Docker Desktop when you don't use it: its pipe closes with it. …
ok    hyper-v: not in Hyper-V Administrators: no program you run can open a VM
ok    wsl disks: 2 distributions' disks are files you own: Ubuntu, Debian. …
```

**`tir doctor --reach`** adds the contents, one block per environment, names only:

```text
docker engine (docker_engine, 3 containers, 5 images)
  api-dev (running, devcontainer C:\src\shop)     OPENAI_API_KEY, DATABASE_URL (user info)
  redis (stopped)                                 REDIS_PASSWORD
  image shop-api:latest                           STRIPE_SECRET_KEY (baked in)
  mounts                                          api-dev: %USERPROFILE%\.ssh
devcontainers
  C:\src\shop\.devcontainer\devcontainer.json     containerEnv: OPENAI_API_KEY
  forwarding                                      git credentials, docker logins
wsl
  Ubuntu (running)     /home/alice/.aws/credentials [default, prod], /home/alice/.ssh/id_ed25519, /home/alice/.bash_history
  Debian (stopped)     disk is a file you own; contents not read (it would start)
hyper-v
  not a member; no readable VM files in the default folders
```

The fixes follow as today's `tir doctor` prints them.

**The app.** Home's two groups get, at most, one line per environment: "3 containers hold secrets
any program can read", "WSL: Ubuntu holds 3 credential files", "Docker engine is open to every
program you run". Each line's one button is its fix; **Details** lists members. Before the first
contents check, the one opt-in card described under *Consent* takes the place of those lines. No new
window: the Installed page's pattern isn't needed for a list this short.

## Design twice: the probe

| | **A. Typed facts on `IDoctorProbe` (chosen)** | **B. Uniform reach sources** |
|---|---|---|
| Interface | `ReachFacts Reach` (account facts, always) and `Task<ReachContents?> ReachContentsAsync(ReachScope scope, CancellationToken ct)` (opt-in) return one record per environment: `DockerEngine(Pipes, Containers, Images)`, `Devcontainer(Folder, Env, Mounts, Forwarding)`, `WslDistribution(Name, Running, DiskReadable, Homes)`, `HyperV(Member, AdminDenyOnly, Vms, ReadableFiles)` | `IReachSource { string Environment; Task<IReadOnlyList<ReachItem>> ScanAsync(ReachScope, CancellationToken) }`, one per environment, each yielding `ReachItem(Environment, Location, Name, ItemKind)`. The planner judges items uniformly |
| Reachability conditions | Explicit fields (pipe DACL, enabled vs deny-only, running vs stopped), so each finding's text and fix can say exactly why | Folded into `ItemKind` or lost; a "why" field would grow back into A's records |
| Names only | Records have no field that can hold a value; the `NameScan` returns names; a reflection test walks every string in a fixture's facts for the canary | `ReachItem.Name` is a string a source could fill with a value; the same canary test, but every new source is a new way to get it wrong |
| A new environment (Podman, Hyper-V on a remote host) | A new record and planner case | A new source, no planner change, until it needs its own fix |
| Matches the repo | `IDoctorProbe`'s pattern: facts in, checks out (`Extensions()`, `CliConfigs`, `AdminTier`) | A plugin seam the doctor doesn't have anywhere else |
| Cost | Four records and their planner cases | Fewer types now, more conditionals in the planner later |

A wins. The findings are only useful with the exact reason ("open while Docker Desktop runs",
"stopped but its disk is yours"), and A carries it as data the planner can test. B's generality
serves environments nobody has asked for. From B, A keeps two ideas: contents come from one async,
cancellable call with a scope (which environments the user opted into), and all name extraction goes
through one `NameScan`, never per source.

```csharp
public interface IDoctorProbe
{
    // ...existing members...

    /// <summary>What your account can open: engine pipes, group membership, distribution disks. No contents.</summary>
    ReachFacts Reach => ReachFacts.None;

    /// <summary>Names inside the environments in <paramref name="scope"/>; <c>null</c> when not asked. Never a value.</summary>
    Task<ReachContents?> ReachContentsAsync(ReachScope scope, CancellationToken ct) => Task.FromResult<ReachContents?>(null);
}

[Flags] public enum ReachScope { None = 0, Docker = 1, Devcontainers = 2, Wsl = 4, HyperV = 8, All = 15 }

// Tiresias.Core, pure: spans in, names out.
public static class NameScan
{
    public static IReadOnlyList<ScannedName> EnvLines(ReadOnlySpan<byte> text);   // NAME=value
    public static IReadOnlyList<ScannedName> IniKeys(ReadOnlySpan<byte> text);    // [section] and key=
    public static IReadOnlyList<ScannedName> JsonKeys(ReadOnlySpan<byte> json, string objectPath);
}
public readonly record struct ScannedName(string Name, bool Empty, bool IsReference, bool HasUserInfo);
```

The planner (`Doctor.Reach(ReachFacts, ReachContents?, dismissals)`) is pure; the Agent's
`ReachProbe` does the pipe, WMI, registry and file I/O.

## Tests

Planner cases with fake facts, `NameScan` cases with byte fixtures:

- a canary value in every fixture (engine JSON, `.env`, INI, `devcontainer.json`) never appears in
  any check's `Name`, `Detail`, `Instruction`, nor in any string reachable from `ReachFacts` or
  `ReachContents` (reflection walk);
- `NameScan` clears its buffer (a test over a caller-owned buffer); malformed input yields no names,
  never an exception;
- `${localEnv:X}` and `%X%` values are not reported; `postgres://u:p@h/db` reports
  `DATABASE_URL (user info)`; `postgres://h/db` doesn't;
- the engine pipe absent: no finding; present and granted: one finding; present and not granted: none;
- Hyper-V enabled: finding; deny-only Administrators only: "an administrator prompt away", not a finding;
- a stopped distribution is never read (the fake probe throws if asked), and still yields the disk line;
- `docker-desktop` distributions are skipped;
- without opt-in, `ReachContentsAsync` is not called, and the contents line says how to run it;
- each fix's instruction names only `tir env set`, `tir run`, `docker`, `wsl` or a VS Code setting,
  checked against `CliUsage.Text` for the `tir` ones.

## Later: devcontainers that ask instead of carrying

Designed on its own page: [devcontainers that ask](devcontainers.md). A devcontainer gets no
secrets at start; a small client in it asks the agent through Docker Desktop's
`host.docker.internal` relay, with a per-folder ticket, and consent names the devcontainer.

## Phases

Each slice ships alone, with its tests and its line in `CHANGELOG.md`.

1. **Account facts.** Pipe DACLs, Hyper-V membership (enabled vs deny-only), the WSL distribution
   list and disk ownership; the three checks in `tir doctor` and on Home. No contents, no opt-in
   needed. **Built**: `ReachProbe` reads each security descriptor with `READ_CONTROL` and the pure
   `ReachAccess` decides who it grants (a deny wins; an owner can read a disk); Hyper-V counts as
   installed when the `vmms` service exists. Docker Desktop keeps `dockerDesktopWindowsEngine` open
   in Linux mode too, so the finding says that pipe is administrator *when Windows containers are
   on*. **How to close it** opens this page's *Findings*.
2. **`NameScan` and devcontainer files.** The pure scanner with the canary tests; `devcontainer.json`
   and its `.env`/Compose files under the project folders; VS Code's forwarding settings;
   `InjectAtRunTime`. Still no engine. **Built**, with these differences: devcontainer files are
   read with the project walk (`--projects`, or the secrets editor's folders) like `appsettings`,
   not behind the opt-in, since they are the user's own files in folders they pointed at. Read are
   `containerEnv`, `remoteEnv`, `runArgs`' `-e`/`--env` and the `--env-file` files (looked for
   against the workspace, then the file's folder); Compose files are not read yet. A URL value is
   reported only with a password in it (`DATABASE_URL (password in URL)`), not for a user name
   alone. Forwarding reads the two VS Code settings when the Dev Containers extension is installed;
   the host `ssh-agent` is left to phase 4. **Copy command** copies the `tir env set` and
   `tir run -- code .` lines; VS Code must be quit first, or `code` hands the folder to the running
   window, which never sees the values.
3. **Docker engine contents, opt-in.** `tir doctor --reach`, the app's card and setting, containers,
   images and mounts, the `devcontainer.local_folder` link to phase 2's folders. **Built**, with
   these differences: the probe never looks on its own; the caller passes what it read into
   `Doctor.RunAsync`, so `tir doctor` looks only with `--reach` and the app only after **Check now**
   (or daily, once ticked). The app keeps the last look in memory for its lifetime, so Home and
   the background checks keep showing its findings between looks; nothing about contents is
   written to disk. Only Docker is read, over whichever open pipe answers first, with GETs only and
   at most 200 containers and 200 images inspected; each call has 10 seconds, its body included. A container or image gone or too large to inspect is left out and counted on the passing line, but the two lists must answer whole, or the check says Docker didn't answer rather than that it found nothing. A container's own names are its `Config.Env`
   minus the names its image reports as secret; those are reported once, on the image. The fix runs the container with
   `docker run --rm -e NAME`, because a value passed with `-e` still lands in the container's
   config and `--rm` takes it away with the container. A `devcontainer.local_folder` label is
   followed only when it is a folder on a local drive, never a UNC path in either slash, since
   opening a WSL path would start its distribution. The fix stops and removes the old container.
4. **WSL contents.** Running distributions only; known credential files and `.env` names; the
   `WSLENV` fix. **Built**, with these differences: it rides on phase 3's opt-in (`--reach`,
   **Check now**, daily), which now looks in Docker and WSL together. Only distributions that
   `wsl.exe --list --running --quiet` names *and* the registry lists are opened, so a message in
   its output is never taken for one; a distribution that stops between the list and the read is
   the one way a look can start one. Every `/home/*` and `/root` is looked in, and paths are shown
   as Linux paths (`/home/alice/.aws/credentials`), not `~`. Only regular, non-empty files count:
   links are not followed and a FIFO is never opened. Azure and gcloud are found by their token
   files (`~/.azure/msal_token_cache.json`, `~/.config/gcloud/credentials.db` and
   `application_default_credentials.json`) rather than their folders, which stay after a sign-out.
   AWS names the sections that set `aws_secret_access_key` or `aws_session_token`; Docker names
   registries with a stored `auth` or `identitytoken`; `.npmrc`, `.pypirc` and `gh`'s `hosts.yml`
   count only with a literal token line (npm's `${NPM_TOKEN}` doesn't); `.env` files in each home
   and one folder down give their secret-looking names. Shell history is listed beside other
   files but never makes a finding on its own. Stopped distributions are named on the passing
   line as not read.
5. **Hyper-V detail.** WMI for members, file DACLs for everyone. **Built**, with these
   differences: it rides on the same opt-in as phases 3 and 4. Access is judged against the token
   *without* Hyper-V Administrators, since a member reads everything through the group already and
   the membership finding covers that; a file is a finding only when another of the token's
   entries (the user, `Users`, `Authenticated Users`, an owner) grants read. Configuration files
   (`.vmcx`) hold no guest data and are left out. Members get the VMs' names on the passing line;
   their disk paths (`Msvm_StorageAllocationSettingData`) and configuration, checkpoint and
   saved-state folders (`Msvm_VirtualSystemSettingData`) are added to the default folders, each
   walked at most six levels deep, skipping links; at most 500 files are checked, the rest counted.
   The finding has no positions: what it opens isn't a secret Tiresias holds.
6. **Devcontainers that ask:** [devcontainers.md](devcontainers.md); tickets, the endpoint and `tir-remote` built, the published feature and git credentials not yet.

## Not in scope

- **Reading a value to judge it.** No check decodes a token, tries it, or searches history for one.
- **Starting, stopping or changing anything.** Fixes print or copy commands; Tiresias runs none of
  them against an engine, a distribution or a VM.
- **Other users' environments.** Only your account's view, without admin rights.
- **Podman, other hypervisors (VMware, VirtualBox).** Same shape, when someone asks: a pipe or a disk
  file with a DACL.
- **Docker's host `config.json` `auths`.** Already listed under [more checks](more-checks.md#later)
  as a host file check.
