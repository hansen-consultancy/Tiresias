namespace Tiresias.Remote;

/// <summary>What <c>tir-remote</c> was asked to do, from its arguments.</summary>
/// <param name="Names">The variables asked for; <c>null</c> for all sealed for the devcontainer's folder.</param>
/// <param name="Command">For <c>run</c>: the command and its arguments. Empty for <c>env</c>.</param>
sealed record RemoteCommand(IReadOnlyList<string>? Names, IReadOnlyList<string> Command)
{
    public const string Usage = """
        tir-remote run [--only NAME[,NAME...]] -- <command> [args...]
            Asks the Tiresias app on the host for the sealed variables of this devcontainer's
            folder, then runs the command with them. The app asks you first.
        tir-remote env <NAME>
            Prints one variable's placeholder or value, for a tool that reads it from stdin.
        """;

    /// <returns><c>null</c> for arguments that aren't a command, with <see cref="Usage"/> to show.</returns>
    public static RemoteCommand? Parse(IReadOnlyList<string> args)
    {
        if (args is ["env", var name] && name.Length > 0 && !name.StartsWith('-'))
            return new([name], []);
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
