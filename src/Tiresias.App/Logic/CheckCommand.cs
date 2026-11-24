using System.Text.RegularExpressions;

namespace Tiresias.App.Logic;

/// <summary>
/// The <c>tir</c> command a check's detail tells you to run ("... run tir trust bind-hello"), so
/// the line can offer it to copy instead of making you retype it.
/// </summary>
public static partial class CheckCommand
{
    /// <returns>The command, or <c>null</c> when the detail names none.</returns>
    public static string? Of(string detail) =>
        Run().Match(detail) is { Success: true } match ? match.Groups["command"].Value : null;

    // Words after "run", up to punctuation; "again" closes a sentence rather than the command.
    [GeneratedRegex(@"\brun (?<command>tir(?: (?!again\b)[a-z][a-z-]*)+)")]
    private static partial Regex Run();
}
