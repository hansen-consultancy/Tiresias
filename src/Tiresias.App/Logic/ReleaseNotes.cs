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

    /// <summary>
    /// The changelog's markdown as plain text for a text box: headings without their hashes, bullets
    /// as "•", no bold or code marks, and each paragraph or bullet on one line (the file wraps them).
    /// </summary>
    public static string Plain(string markdown)
    {
        var lines = new List<string>();
        foreach (var raw in markdown.ReplaceLineEndings("\n").Split('\n'))
        {
            var line = raw.Trim().Replace("**", "", StringComparison.Ordinal).Replace("`", "", StringComparison.Ordinal);
            var bullet = line.StartsWith("- ", StringComparison.Ordinal);
            if (line.Length > 0 && !bullet && !line.StartsWith('#', StringComparison.Ordinal) && lines.Count > 0 && lines[^1].Length > 0)
                lines[^1] += " " + line;
            else if (line.StartsWith('#', StringComparison.Ordinal))
                lines.Add(line.TrimStart('#').TrimStart());
            else
                lines.Add(bullet ? "• " + line[2..] : line);
        }
        return string.Join('\n', lines);
    }
}
