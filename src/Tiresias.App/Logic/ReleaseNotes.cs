namespace Tiresias.App.Logic;

/// <summary>
/// One version's section of <c>CHANGELOG.md</c>, the same text <c>.github/scripts/release-notes.sh</c>
/// publishes as the release notes: the lines after <c>## [version]</c> up to the next <c>## [</c>.
/// </summary>
public static class ReleaseNotes
{
    /// <param name="version">A version, or <c>Unreleased</c> for what a development build has on top.</param>
    /// <returns>The section without surrounding blank lines, or <c>null</c> when it is missing or empty.</returns>
    public static string? Section(string changelog, string version)
    {
        var heading = $"## [{version}]";
        var lines = changelog.ReplaceLineEndings("\n").Split('\n');
        var start = Array.FindIndex(lines, l => l.StartsWith(heading, StringComparison.Ordinal));
        if (start < 0)
            return null;
        var end = Array.FindIndex(lines, start + 1, l => l.StartsWith("## [", StringComparison.Ordinal));
        var section = string.Join('\n', lines[(start + 1)..(end < 0 ? lines.Length : end)]).Trim('\n', ' ');
        return section.Length == 0 ? null : section;
    }
}
