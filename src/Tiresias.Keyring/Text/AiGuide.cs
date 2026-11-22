namespace Tiresias.Keyring;

/// <summary>
/// <c>tir ai</c>: what an AI coding agent on this machine needs to know to get credentials through
/// Tiresias. <see cref="Block"/> is the few lines a user pastes (or <c>tir ai --install</c> writes)
/// into CLAUDE.md or AGENTS.md; it only points at <c>tir ai</c>, so it stays right as
/// <see cref="Instructions"/> follow the installed version. Every <c>tir</c> command and flag named here is checked against <see cref="CliUsage"/>.
/// </summary>
static class AiGuide
{
    public const string Snippet = """
        ## Credentials: Tiresias

        This machine has Tiresias (`tir`), a credential broker. Before a task needs an API key, token,
        password or connection string, or an authenticated call, run `tir ai` and follow what it says.
        Never read, print or ask the user for a secret value.
        """;

    public const string Begin = "<!-- tiresias:begin -->";
    public const string End = "<!-- tiresias:end -->";

    /// <summary>The snippet between markers, so an install finds and replaces it, pasted by hand or not.</summary>
    public const string Block = Begin + "\n" + Snippet + "\n" + End;

    /// <summary>
    /// The file's text with <see cref="Block"/> in it: in place of the one between the markers, or
    /// appended after a blank line. Keeps the file's line endings; the same text when it is current.
    /// </summary>
    public static string Install(string? existing)
    {
        existing ??= "";
        var newline = existing.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var block = Block.ReplaceLineEndings(newline);
        var begin = existing.IndexOf(Begin, StringComparison.Ordinal);
        if (begin >= 0)
        {
            var end = existing.IndexOf(End, begin, StringComparison.Ordinal);
            if (end < 0)
                throw new InvalidOperationException($"The file has \"{Begin}\" but no \"{End}\" after it. Remove the Tiresias section by hand, then install again.");
            return existing[..begin] + block + existing[(end + End.Length)..];
        }
        if (existing.Length == 0)
            return block + newline;
        var separator = existing.EndsWith(newline + newline, StringComparison.Ordinal) ? ""
            : existing.EndsWith(newline, StringComparison.Ordinal) ? newline
            : newline + newline;
        return existing + separator + block + newline;
    }

    public const string Instructions = """
        # Tiresias: credentials for AI agents

        Tiresias (`tir`) is installed on this machine. It keeps API keys, tokens, database logins and
        .NET user secrets sealed behind Windows Hello. A program gets a short-lived placeholder
        (`tirph_...`) or the value only after the user approves it in the Tiresias app, and every
        request is recorded in the app's Activity. Use it whenever a task needs a credential.

        ## Rules

        - Never read, print, log, copy or commit a secret value. Never ask the user to paste one into
          the chat, a file or a command line: give them the `tir` command that asks for it without
          echo, and let them run it.
        - Don't look for credentials elsewhere: `.env` files, `secrets.json`, `NuGet.Config`, `.npmrc`,
          `~/.git-credentials`, user environment variables, a CLI's token cache.
        - A request opens a consent dialog (and often Windows Hello) on the user's screen, and the
          command waits for the answer. Say what you are about to run and why before you run it. A
          "no" is final: don't retry it or work around it.
        - Setup is the user's: suggest `tir service add`, `tir env set`, `tir env protect`,
          `tir secrets set`, `tir unlock`, but don't run them. Never run `tir agent`: it is a
          long-running host the user starts in their own terminal.

        ## Look first

        tir status                  is the app running, is a lease open (no prompt)
        tir service list            services `tir exec` can call (no prompt)
        tir doctor                  where credentials on this machine are exposed (no prompt)
        tir advise "<need>"         the ways to meet a need, e.g. "OpenAI key for a script"
        tir env list                sealed environment variable names (one Windows Hello prompt)
        tir secrets list            the current project's user-secret keys (one Windows Hello prompt)

        None of these prints a value.

        ## Call an HTTP API, SQL Server or GitHub without the secret

            tir exec <service>[,<service>...] --purpose "<why, in a few words>" [--for 1h] -- <command> [args...]

        The command runs with placeholders in its environment, revoked when it exits:

        - HTTP service: `<SLUG>_TOKEN` (a placeholder) and `<SLUG>_BASE_URL`. Send requests to
          `<SLUG>_BASE_URL` plus the API path, with `Authorization: Bearer <SLUG>_TOKEN`; the broker
          puts the real credential in on the way out, only for the methods and paths its grant allows.
        - SQL Server service: `<SLUG>_TOKEN` and `<SLUG>_SQL_URL`, plus `<SLUG>_CONNECTION_STRING`
          when the grant hands out a temporary login.
        - GitHub App service: `GH_TOKEN` and `GITHUB_TOKEN`, an installation token valid up to an hour,
          for `gh` and the GitHub API.

        `<SLUG>` is the service name in upper case, other characters as `_` (`llm-prod`: `LLM_PROD`).
        Read-only grants are the default; a write may need the user to run `tir elevate`.

        ## Sealed environment variables

            tir run [--only NAME[,NAME...]] -- <command> [args...]

        Runs the command with the variables sealed for the current folder. A variable set up as a
        placeholder arrives as `tirph_...` with its base-URL variable (`OPENAI_API_KEY` with
        `OPENAI_BASE_URL`), which OpenAI-compatible SDKs pick up as is. Use `--only` to ask for no more
        than the command needs. npm and twine get their tokens this way too.

        ## No command needed

        - .NET user secrets: an app using `Tiresias.Extensions.Configuration` gets them on `dotnet run`
          after the user allows it. Don't open or edit `secrets.json`; to change a key, the user runs
          `tir secrets set <key>`.
        - NuGet feeds: `dotnet restore`, Visual Studio and Rider ask Tiresias's credential plugin; the
          user approves a program for the exact feed URL, username and variable, once or for the session.

        ## When something is missing

        Not a service, no sealed variable, the app not running, or locked: stop and tell the user what
        you need and why, with the command that would set it up (`tir advise "<need>"` lists the
        options). Don't fall back to a plain-text secret.
        """;
}
