namespace Tiresias.App.Logic;

/// <summary>One line of a list row's details panel: a label and the value a narrow column cut short.</summary>
public sealed record DetailField(string Label, string Value);

/// <summary>A row's details as the panel shows them and as Copy puts them on the clipboard.</summary>
public static class DetailText
{
    /// <summary>The fields that say something: an empty value is left out rather than shown as a bare label.</summary>
    public static IReadOnlyList<DetailField> Shown(IEnumerable<DetailField> fields) =>
        [.. fields.Where(f => !string.IsNullOrWhiteSpace(f.Value))];

    /// <summary>"Label: value" per line; a value of several lines keeps them, indented under its label.</summary>
    public static string Format(IEnumerable<DetailField> fields) =>
        string.Join(Environment.NewLine, Shown(fields).Select(f =>
            $"{f.Label}: {string.Join(Environment.NewLine + "  ", f.Value.ReplaceLineEndings("\n").Split('\n'))}"));
}
