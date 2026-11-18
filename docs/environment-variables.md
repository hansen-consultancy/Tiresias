# Environment variables

**Status:** phase 1 is built: the store, **Protect** / **Put back**, `tir env`, `tir run`, the
**Environment variables** window and the status check. Phases 2 to 4 are design.

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
a sealed variable writes it to the registry again, so the move is never a trap. Machine-level
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

One line in the PowerShell profile (the app offers to add it, and `tir env hook` prints it):

```powershell
tir env hook pwsh | Invoke-Expression
```

The hook asks the agent over its pipe for the set for the current directory. The first request
from a shell process asks for consent (a dialog naming the shell, its folder and the variable
names). Once allowed, that shell process is remembered, keyed by its process id and start time,
until it exits or the agent locks. Changing directory re-resolves the set: variables from the old
folder are removed, the new folder's are added, with no new prompt unless a folder set adds
variables the session has not been allowed.

A locked agent leaves the terminal working, without the variables, and the prompt shows a short
`tiresias: locked` hint once.

### For one command

`tir run [--] <command> [args...]` resolves the set for the current directory, asks once, and
starts the command with the variables in its environment only. For scripts, CI-like runs, and
shells without a hook (cmd, Git Bash).

### Placeholders instead of values

A variable can be switched to **placeholder** delivery when it is an API key for a service the
vault knows. The real key moves into the vault as that service; the process gets a placeholder in
the variable and the forwarder's URL in the tool's base-URL variable (for example
`OPENAI_BASE_URL`), so it never holds the key at all. It works only for tools that honour such a
variable, and the editor says so rather than offering it everywhere.

### Programs started outside a shell

- **NuGet:** a credential provider (`Tiresias.NuGet.CredentialProvider`, NuGet's plugin protocol)
  answers for package sources the user maps to sealed variables. `dotnet restore`, Visual Studio
  and Rider then authenticate without a token in `NuGet.Config` or the environment. Consent is per
  program, as for user secrets.
- Anything else that only reads its environment at start-up stays in the registry, and the status
  page lists it as **unprotected** with the program that needs it, so the gap is visible rather
  than hidden.

## Honest limits

- A process given a real value holds it in memory and can pass it to its children or write it
  anywhere. Placeholder delivery is the answer where a tool allows it.
- A whole terminal session sharing the values means anything run from that terminal gets them.
  That is the trade-off chosen over a prompt per command.
- The activity log records variable names, the program and the decision; never a value.

## Phases

1. Store, **Protect** / **Put back**, `tir env`, `tir run`, and an **Environment variables** window
   (tray menu, and **Review...** on the status check). Built.
2. The shell hook with session consent and folder sets.
3. Placeholder delivery through the vault and forwarder.
4. The NuGet credential provider.
