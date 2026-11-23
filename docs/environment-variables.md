# Environment variables

**Status:** built: the store with folder sets, **Protect** / **Put back**, `tir env`, `tir run`,
the PowerShell hook with consent once per terminal, the **Environment variables** window, the
status check, placeholder delivery and the NuGet credential plugin.

Many developers keep API keys and tokens in their Windows user environment (`setx OPENAI_API_KEY
...`). That makes them readable by every process the user starts, forever, with no record of who
read them: exactly what Tiresias exists to stop. This page is the plan for sealing them, and for
handing them back to the programs that need them.

## Decisions

| Question | Decision |
|---|---|
| How a program gets a value back | **Per variable:** the real value, injected into the process that runs, or a broker placeholder (`tir exec`'s model) for an HTTP API key whose tool honours a base-URL variable |
| Programs not started from a shell (IDEs, `dotnet restore` from an IDE) | **Per-tool integration**, starting with a NuGet credential provider. Anything else stays in the registry and is reported as unprotected |
| How often consent asks | **Once per shell session:** the first use in a terminal asks; that terminal and its children keep the values until it closes or the agent locks |
| Scope | **Global plus per folder:** one global set; a folder can add or override variables for commands run inside it |

## Moving variables in

The app's status page, and `tir doctor`, list user environment variables whose **names** look like
secrets (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*_PWD`, connection strings). Values are
never shown, only their length. Paths and well-known Windows variables are never offered.

**Protect...** opens a list with the likely secrets ticked. For each one picked:

1. The value is sealed into the environment store (below).
2. The sealed copy is opened again and compared, so nothing is removed that can't be read back.
3. The variable is deleted from `HKCU\Environment`, and `WM_SETTINGCHANGE` is broadcast so new
   processes stop inheriting it.

Programs already running keep their copy until they restart; the dialog says so. **Put back** on
a sealed variable writes it to the registry again, so the move is never a trap. `tir env set` for a name
still in the registry seals the new value, then deletes the old copy there. Machine-level
variables need elevation and are reported, not moved, in the first version.

## The store

`%LOCALAPPDATA%\Tiresias\environment.json`, sealed the way a user-secrets file is: each value encrypted
under a data key wrapped for Windows Hello and for the recovery key, so the recovery restore
covers it with no extra step. It holds:

- the **global** set: name, sealed value, and how it is delivered (value or placeholder);
- **folder** sets: a full path and the variables it adds or overrides. Kept in the store, never in
  the folder, so nothing can be committed to a repository by mistake.

The resolved set for a working directory is the global set, overlaid by each folder set from the
drive root down to that directory; the nearest folder wins.

## Getting values back

### In a terminal

One line, last in the PowerShell profile (`$PROFILE`), after anything else that replaces the
prompt; it works in PowerShell 7 and Windows PowerShell 5.1:

```powershell
tir env hook | Out-String | Invoke-Expression
```

The hook wraps the prompt: when the terminal opens, and whenever the folder changes (never for
each command), it runs `tir env shell`, which asks the app for the set for that folder. The first
request from a shell asks for consent: a dialog naming the shell, its folder and the variable
names. Once allowed, that shell is remembered, keyed by its process id and start time, until it
exits or the agent locks. Changing folder re-resolves the set: variables from the old folder are
removed, the new folder's are added, with no new prompt unless a folder set adds names the
terminal has not been allowed.

- **A no** sticks to that terminal: it keeps what it was allowed before and is not asked again on
  each `cd`. `Update-TiresiasEnvironment -Ask` asks again.
- **Locked:** the first request unlocks (Windows Hello) as part of asking. Cancelling it counts as
  a no for that terminal.
- **Nothing sealed:** no prompt at all, not even to unlock.
- **The app not running:** the terminal works without the variables, and says so once. `tir run`
  still works, with Windows Hello as the consent.

The app believes the shell process id the hook sends only when that process is an ancestor of
the `tir` on the pipe, started before it, so another program can't borrow a terminal's consent by
naming it. Values reach the hook as base64, which PowerShell decodes, so neither the console's
code page nor PowerShell's parser touches them.

### For one command

`tir run -- <command> [args...]` resolves the set for the current directory, asks once, and
starts the command with the variables in its environment only. `--only NAME[,NAME...]` narrows
that to the names given, in the dialog too; a name not sealed for that folder is an error rather
than silently missing. The dialog's **Asked by** is `tir`, the program the app can verify on its
pipe; the heading names the command it is about to start. For scripts, CI-like runs, and
shells without a hook (cmd, Git Bash).

### Placeholders instead of values

A variable can be switched to **placeholder** delivery when it is an API key for an https
service in the vault, whose secret is the key as an `Authorization` header (`Bearer <key>`):

```powershell
tir service add openai --upstream https://api.openai.com/v1   # secret: Bearer sk-...
tir env placeholder add OPENAI_API_KEY openai                  # base URL: OPENAI_BASE_URL
```

From then on a terminal or `tir run` gets a `tirph_` placeholder in `OPENAI_API_KEY` and the
forwarder's `/svc/openai` (the solo broker's, without a forwarder) in `OPENAI_BASE_URL`, so the
process never holds the key. The broker swaps the real header in on the way out, under the
service's grants, and the activity log records each request.

- **The base-URL variable** follows the key's name (`*_API_KEY`, `*_KEY`, `*_TOKEN` become
  `*_BASE_URL`); `--base-url` names another. It can't be a sealed variable itself.
- **Consent** lists the variable as a placeholder for its service. The placeholder is minted after
  the answer, for at most 10 hours and never past the broker's lease (a workday lease ends at its
  daily cutoff).
- **A terminal** keeps one placeholder per variable, so changing folder doesn't mint another; one
  with less than 30 minutes left before the expiry the broker gave it is replaced at the next
  folder change, and the old one revoked.
  A terminal's placeholders are revoked once it has exited (noticed at the next request from any
  terminal), and all of them when Tiresias locks.
- **`tir run`** revokes its placeholders when the command exits, as `tir exec` does.
- **No placeholder** (broker unreachable, service missing, no lease): the variable is left out
  and the reason shown. It never falls back to the real value.
- `tir env placeholder list` shows the deliveries, `remove` switches a variable back to its value.
  The environment variables window does both: check a sealed key, pick the service under **Hand
  out a placeholder instead**, then **Use a placeholder**; **Hand out the value** undoes it.
  The sealed value stays, so **Put back** and `remove` lose nothing.
- The status page finds sealed keys handed out as values where a placeholder would do, and its
  **Use a placeholder...** opens this window with the key checked. It needs Tiresias unlocked,
  since the names are sealed too; `tir doctor` says it skipped the check.
- Only tools that send the key as `Authorization: Bearer` and read a base-URL variable work this
  way: the OpenAI SDKs and most OpenAI-compatible clients do. A tool sending the key in another
  header (Anthropic's `x-api-key`) gets refused by the broker: keep that one as a value.

- **npm and PyPI:** `tir env import <file> <entry> <NAME>` seals a token an `.npmrc` (the entry
  is its key, `//registry.npmjs.org/:_authToken`) or a `.pypirc` (the entry is its section) holds
  in plain text, then takes it out of the file. An `.npmrc` is left with `${NAME}`, which npm fills
  in from the environment `tir run` and the terminal hook give it; a `.pypirc` loses its
  `password`, and twine reads `TWINE_PASSWORD` instead (for the `pypi` section, which `tir doctor`
  offers to seal). The token is read once to seal it and never shown. `tir doctor` and the status
  page find these, and the status page's **Seal token...** does the same after a yes.

### Programs started outside a shell

- **NuGet:** `nuget-plugin-tiresias.exe`, installed next to `tir`, speaks NuGet's
  cross-platform credential plugin protocol (version 2). `tir env nuget import` (or **Move to
  Tiresias** under **NuGet feeds** in the environment variables window) finds the sources whose
  `NuGet.Config` credentials are `%NAME%` or a plain-text token, seals the token (from Windows, or
  from the file), maps the source, and takes its credentials out of the file: NuGet only asks a
  plugin when the config has none. An encrypted `Password` can't be read, so it is left with a
  note. `tir env nuget list` shows what is mapped and what is still in `NuGet.Config`. By hand:
  `tir env nuget add <source-url> <NAME> [--username <name>]`, then remove the credentials. When the feed answers 401, NuGet asks the plugin; the plugin asks the app, and
  the app asks you once per program (the parent of the plugin: `dotnet`, `devenv`, `MSBuild`...)
  and variable, with **Allow for this session** remembered until Tiresias locks.
  - The plugin answers only for https sources on the mapped host and port: the source itself, or
    anything under the folder its service index is in. Everything else is **NotFound**, so NuGet
    carries on with its other providers.
  - A retry (the feed refused the last answer) gets no value, only a message saying which
    variable to reseal.
  - The mapping is sealed with the variables, so nothing can quietly point a token at another host.
  - NuGet finds `nuget-plugin-*` on PATH from NuGet 6.13 (.NET SDK 9.0.200, Visual Studio 17.13);
    older ones also wanted plugins Authenticode-signed. Don't set `NUGET_PLUGIN_PATHS`: it
    replaces NuGet's own discovery.
- **.NET apps** started by an IDE (F5 in Visual Studio or Rider) read environment variables
  through configuration: see [.NET configuration](#net-configuration) (designed, phase 5).
- Anything else that only reads its environment at start-up stays in the registry, and the status
  page lists it as **unprotected** with the program that needs it, so the gap is visible rather
  than hidden.

## .NET configuration

**Status:** built: `environment.load`, the provider, `tir env config` and `tir env protect --config`.
Not yet built: the checkbox in the window and in the Protect dialog.

.NET's default host reads every environment variable into configuration, under its own name
(`Payments__ApiKey` becomes `Payments:ApiKey`, `OPENAI_API_KEY` stays `OPENAI_API_KEY`). Many apps get a shared signing key or API key that way, with no setup. Once
**Protect** seals such a variable, an app started from a terminal with the hook, or by `tir run`,
still gets it. One started by an IDE does not: the IDE's environment never had it, and its debug
child inherits that. Starting the IDE itself through `tir run` works, but hands every sealed
variable allowed to the IDE and everything it starts for as long as it runs.

`Tiresias.Extensions.Configuration` already sits in such an app's configuration (its generator
intercepts `CreateBuilder` and `AddUserSecrets`). It gains a second source: **sealed
configuration variables**, asked of the app by the app being configured, not by its parent.

- **Which variables:** only those marked for configuration delivery, a third delivery beside value
  and placeholder, set per variable (`tir env config add <NAME>`; a checkbox in the window is to come).
  Any sealed variable can be marked: the name says nothing about whether an app reads it, since
  the host injects them all. Nothing is handed to an app it wasn't marked for,
  and an app never sees the whole sealed set the way a terminal does.
- **Folder sets apply** by the app's working directory, so a folder can override a global value
  for one solution.
- **Where it sits:** just before the unprefixed environment-variables source the host added. It
  sets the allowed variables in the process environment, and that source reads them: same keys,
  same precedence as from `HKCU\Environment`, and children the app starts get them too. A builder
  without that source reads no environment, so it gets nothing, as before. It asks once per
  process however often the host rebuilds its sources.
- **Already in the environment wins:** a name the process already has (a terminal with the hook,
  `tir run`) is not asked for, so there is no second prompt and no surprise override.
- **Consent:** the dialog names the program (the process on the pipe, by image path), its folder
  and the variable names. **Allow for this session** is remembered per image path and folder until
  Tiresias locks, so each F5 doesn't ask again; a rebuilt binary at the same path keeps the answer.
  Policy (blocked programs, frozen) is checked as for the terminal hook.
- **No agent:** a 300 ms glance, then the app starts without the variables, silently. It never
  waits 60 seconds as sealed user secrets do: an app on a machine without Tiresias would hang at
  every start. A refusal is one line on stderr.
- **Locked:** the request unlocks with Windows Hello as part of asking, as `tir run` does.
- **Placeholders** are not delivered this way: a variable is either a placeholder or marked for
  configuration.
- **Wire:** a new agent pipe op, `environment.load`, carrying the app's folder and the names it
  already has; the reply's JSON maps variable names to values. An older agent answers it with an
  error, and the app starts without them.
- **Protect asks:** `tir env protect --config` marks what it seals; without it, it says that
  programs started outside a terminal stop seeing them. The Protect dialog's **Also for .NET apps**
  checkbox is to come.

What it does not cover: an app that doesn't reference the package (one `PackageReference`, often
in a shared `Directory.Build.props`), and non-.NET programs started by an IDE. Those keep
`tir run` around the IDE, or **Put back**.

## Honest limits

- A process given a real value holds it in memory and can pass it to its children or write it
  anywhere. Placeholder delivery is the answer where a tool allows it.
- A whole terminal session sharing the values means anything run from that terminal gets them.
  That is the trade-off chosen over a prompt per command.
- A program running as you could start `tir` with a forged parent and so pass for an allowed
  terminal. It gains nothing it couldn't take anyway: a program running as you can read that
  terminal's memory, environment included. Sealing protects against reading the registry, files
  and new processes, not against malware already running as you.
- The activity log records variable names, the program and the decision; never a value.
- The NuGet plugin has been tested against the protocol as documented, not yet against a real
  `dotnet restore`. In particular, which NuGet hosts (the .NET SDK, MSBuild under Visual Studio,
  `nuget.exe`) look on PATH is not spelled out by NuGet's documentation.
- The program asking for a NuGet token is the plugin's parent process. A program running as you
  can start the plugin itself and pass for `dotnet`; as above, it could read `dotnet`'s memory
  anyway.

## Phases

1. Store, **Protect** / **Put back**, `tir env`, `tir run`, and an **Environment variables** window
   (tray menu, and **Review...** on the status check). Built.
2. The shell hook with session consent and folder sets (`tir env hook`, `--folder`, a folder field
   in the window). Built.
3. Placeholder delivery through the vault and forwarder (`tir env placeholder`). Built.
4. The NuGet credential plugin (`tir env nuget`, `nuget-plugin-tiresias.exe`). Built.
5. Sealed configuration variables for .NET apps started outside a terminal (`environment.load`,
   `tir env config`, `protect --config`). Built; the window's checkboxes to come.
