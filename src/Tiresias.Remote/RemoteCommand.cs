namespace Tiresias.Remote;

/// <summary>What <c>tir-remote</c> was asked to do, from its arguments.</summary>
/// <param name="Names">The variables asked for; <c>null</c> for all sealed for the devcontainer's folder.</param>
/// <param name="Command">For <c>run</c>: the command and its arguments. Empty for <c>env</c>.</param>
/// <param name="Git">For <c>git-credential</c>: the action git asks of a credential helper (<c>get</c>, <c>store</c>, <c>erase</c>).</param>
sealed record RemoteCommand(IReadOnlyList<string>? Names, IReadOnlyList<string> Command, string? Git = null)
{
    public const string Usage = """
        tir-remote run [--only NAME[,NAME...]] -- <command> [args...]
            Asks the Tiresias app on the host for the sealed variables of this devcontainer's
            folder, then runs the command with them. The app asks you first.
        tir-remote env <NAME>
            Prints one variable's placeholder or value, for a tool that reads it from stdin.
        tir-remote git-credential get
            A git credential helper: asks the app for the token mapped to the remote's host
            (tir env git add on the host). The Tiresias devcontainer feature sets it up.
        """;

    /// <returns><c>null</c> for arguments that aren't a command, with <see cref="Usage"/> to show.</returns>
    public static RemoteCommand? Parse(IReadOnlyList<string> args)
    {
        if (args is ["env", var name] && name.Length > 0 && !name.StartsWith('-'))
            return new([name], []);
        if (args is ["git-credential", var action])
            return new(null, [], action);
        if (args.Count == 0 || args[0] != "run")
            return null;
        var dashes = args.ToList().IndexOf("--");
        if (dashes < 0 || dashes == args.Count - 1)
            return null;
        var options = args.Skip(1).Take(dashes - 1).ToArray();
        IReadOnlyList<string>? names = options switch
        {
            [] => null,
            ["--only", var list] when list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) is { Length: > 0 } only => only,
            _ => [],
        };
        return names is [] ? null : new(names, [.. args.Skip(dashes + 1)]);
    }
}

/// <summary>git's credential helper protocol: <c>key=value</c> lines in, ended by a blank line or the end of input; the same out.</summary>
static class GitCredential
{
    /// <summary>What git sent. A key given twice keeps its last value, as git's own parser does.</summary>
    public static IReadOnlyDictionary<string, string> Read(IEnumerable<string> lines)
    {
        var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in lines.TakeWhile(l => l.Length > 0))
            if (line.IndexOf('=', StringComparison.Ordinal) is > 0 and var at)
                attributes[line[..at]] = line[(at + 1)..];
        return attributes;
    }

    /// <summary>The answer to <c>get</c>; <c>null</c> when a part holds a line break, which the protocol can't carry.</summary>
    public static string? Answer(string username, string password) =>
        username.AsSpan().ContainsAny('\n', '\r', '\0') || password.AsSpan().ContainsAny('\n', '\r', '\0')
            ? null
            : $"username={username}\npassword={password}\n";
}
