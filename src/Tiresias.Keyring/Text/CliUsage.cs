namespace Tiresias.Keyring;

/// <summary>What <c>tir</c> prints on a usage error: the command list that <see cref="AiGuide"/> is checked against.</summary>
static class CliUsage
{
    public const string Text = """
        tir enroll --broker <url> --broker-key <base64> [--tenant <name>] [--genesis <hex>] [--device <id>] [--vault <path>]

        Every command but enroll and recovery takes --tenant <name> when the Keyring is enrolled with
        several brokers and the service doesn't settle which.

        tir recovery init
        tir recovery restore
            Gives sealed secrets back to this PC's Windows Hello with the paper recovery key: after
            moving to a new PC, resetting Windows Hello, or copying secrets from another machine.
        tir solo init
            Solo mode: the broker runs inside the Tiresias app on this PC, no server needed. Creates
            the recovery key if there is none (or asks for it) and a one-device trust chain.
        tir solo service install | uninstall
            As administrator: runs the solo broker as the Tiresias Windows service, under its own
            account, so programs running as you can't read its memory. Quit the app first.
        tir trust bind-hello
            Names this PC's Windows Hello key in the trust chain, for a chain made before Tiresias
            asked for it: one Hello prompt and the recovery key, once. Solo mode needs the app running.
        tir vault add <slug> [--from-stdin]
        tir vault migrate     bind secrets saved before Tiresias checked service settings (one Hello prompt)
        tir service add <slug> --upstream <https-url> [--secret <slug>] [--method GET]... [--allow <regex>]...
                        [--deny <regex>]... [--grant <name>] [--elevation] [--from-stdin]
            Adds a service with one grant. The secret defaults to the service's slug and is asked for
            (without echo) when the vault doesn't have it yet; methods default to GET; with no --allow,
            every path is allowed. A solo broker uses the change from its next request.
        tir service list
        tir service remove <slug>
            Removes the service, keeps its secret.
        tir unlock [--secrets a,b]
        tir lock
        tir status
        tir agent
            When the Tiresias app runs, it is the agent: unlock and lock go through it, and grant and
            exec ask for approval in its dialog. tir agent is for when the app isn't running.
        tir grant <service> --consumer <name> --purpose <text> --for <duration> [--ceiling <grant>]
        tir elevate <service> <grant> [--for 15m]
        tir exec <service>[,<service>...] --purpose <text> [--for 1h] [--ceiling <grant>] -- <command> [args...]
        tir doctor [--projects <dir>] [--surface]
            Checks this device and how its credentials are delivered. --projects also looks under <dir>
            for projects without the protected provider, passwords in appsettings*.json connection
            strings, and private keys in files. A finding shows where it sits on the two axes (E5/C3:
            readable, used silently) and where its fix takes it. --surface also lists what is
            installed: extensions with what their host reached, global dotnet/npm/pipx/cargo tools,
            and what starts at log-on with its signature and last use. Read-only and offline.
        tir advise ["<what you need>"]
            The ways to meet a need, strongest first on both axes, and what each gives up: "OpenAI key
            for a script", "my EF Core app talks to Azure SQL". With no words, every need. The words are
            matched on this machine; nothing is sent anywhere.
        tir ai [--snippet | --install [<file>]]
            How AI coding agents (Claude Code, Codex, Copilot...) get credentials through Tiresias
            without seeing them. --snippet prints a few lines for your CLAUDE.md or AGENTS.md, so
            every agent session knows Tiresias is here and runs tir ai. --install writes them into
            ~/.claude/CLAUDE.md, or the file named (~/.codex/AGENTS.md...), replacing an earlier copy.

        tir secrets list [--project <path> | --id <UserSecretsId>]
        tir secrets set <key> [--from-stdin] [--project <path> | --id <UserSecretsId>]
        tir secrets remove <key> [--project <path> | --id <UserSecretsId>]
            A project's protected user secrets (the project in the current folder by default).
            Values are typed without echo or piped in; no command prints one.

        tir env list
        tir env protect [<NAME>...] [--yes]
        tir env put-back <NAME>...
        tir env set <NAME> [--from-stdin] [--folder [<path>]]
        tir env remove <NAME> [--folder [<path>]]
            Environment variables sealed out of your Windows user environment. protect with no names
            offers the ones that look like secrets; put-back returns them to Windows as they were.
            --folder keeps a variable for commands run in that folder (the current one by default)
            and below, adding to or overriding the global set.
        tir env nuget import [--yes]
        tir env nuget add <source-url> <NAME> [--username <name>]
        tir env nuget list
        tir env nuget remove <source-url>
            NuGet package sources that authenticate with a sealed variable: dotnet restore, Visual
            Studio and Rider ask the app for the token, and you allow each program once. import
            finds the sources NuGet.Config gives a token (as %NAME% or in plain text), seals it and
            takes it out of the file.
        tir env import <file> <entry> <NAME>
            Seal the token an .npmrc (entry: its key, //registry.npmjs.org/:_authToken) or a .pypirc
            (entry: its section) holds in plain text as NAME, and take it out of the file. An .npmrc
            then says ${NAME}, which npm fills in from the environment tir run gives it.
        tir env placeholder add <NAME> <service> [--base-url <VARIABLE>]
        tir env placeholder list
        tir env placeholder remove <NAME>
            Hand a sealed API key out as a placeholder for a vault service instead of its value, with
            the forwarder's address in the tool's base-URL variable (OPENAI_API_KEY: OPENAI_BASE_URL).
        tir env hook [pwsh]
            Prints the PowerShell profile hook: tir env hook | Out-String | Invoke-Expression. Each
            terminal asks once for the sealed variables, and changing folder applies its set.
        tir run [--only NAME[,NAME...]] -- <command> [args...]
            Runs the command with the sealed environment variables, after you allow it (in the app's
            dialog, or with Windows Hello when the app isn't running). --only gives it just those.
        tir decoys place <passwords|project|variables> [<path>]
        tir decoys list
        tir decoys remove
            Decoy credentials that open nothing and point to a port only Tiresias listens on, so a
            program that finds and uses one is named in the activity log (and blocked by the app).
            passwords: a passwords.txt (Documents by default); project: a new folder with an
            appsettings.Production.json and a .env; variables: ADMIN_API_URL and ADMIN_API_TOKEN.
            Nothing that exists is overwritten. remove takes away every decoy placed.
        """;
}
