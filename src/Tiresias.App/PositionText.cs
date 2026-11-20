using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App;

/// <summary>A position as the windows show it: words, with their meanings for a tooltip (docs/app-design.md, rule 4).</summary>
public static class PositionText
{
    /// <summary>"Readable, unchecked".</summary>
    public static string Short(Position position) =>
        Text.Format("Position_Pair", Text.Get(PositionWords.Of(position.Exposure).Word), Text.Get(PositionWords.Of(position.Control).Word));

    /// <summary>"Readable, unchecked → Stays in Tiresias, asks you", or one side when there is no better place.</summary>
    public static string Moves(Position? now, Position? better) => (now, better) switch
    {
        ({ } n, { } b) => Text.Format("Position_Moves", Short(n), Short(b)),
        ({ } n, null) => Short(n),
        _ => "",
    };

    /// <summary>What each word means, one line per axis; both positions when the fix moves it.</summary>
    public static string Meaning(Position? now, Position? better) =>
        string.Join(Environment.NewLine, new[] { now, better }.OfType<Position>()
            .SelectMany(p => new[] { PositionWords.Of(p.Exposure), PositionWords.Of(p.Control) })
            .Select(w => Text.Format("Position_Meaning", Text.Get(w.Word), Text.Get(w.Meaning)))
            .Distinct());
}
