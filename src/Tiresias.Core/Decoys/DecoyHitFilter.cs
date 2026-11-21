namespace Tiresias.Decoys;

/// <summary>
/// Keeps a flood of connections from flooding the activity log and the app: a hit is reported
/// once per program and use within <see cref="Window"/>; the repeats add nothing the first didn't say.
/// </summary>
public sealed class DecoyHitFilter
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    const int PruneAbove = 256;

    readonly Lock gate = new();
    readonly Dictionary<(int?, string?, DecoyUse), DateTimeOffset> reported = [];

    /// <summary>Whether to report <paramref name="hit"/>: the first of its program and use, or the first since the window passed.</summary>
    public bool ShouldReport(DecoyHit hit)
    {
        var key = (hit.ProcessId, hit.Program, hit.Use);
        lock (gate)
        {
            if (reported.TryGetValue(key, out var last) && hit.At - last < Window)
                return false;
            if (reported.Count >= PruneAbove)
                foreach (var stale in reported.Where(r => hit.At - r.Value >= Window).Select(r => r.Key).ToArray())
                    reported.Remove(stale);
            reported[key] = hit.At;
            return true;
        }
    }
}
