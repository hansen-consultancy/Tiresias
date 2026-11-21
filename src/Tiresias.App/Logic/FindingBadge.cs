using System.Text.Json;
using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>
/// The tray's badge: how many findings Home would show that the user hasn't seen there yet. A
/// finding is known by <see cref="Dismissals.KeyOf"/>, so one that comes back changed is new again,
/// and a dismissed one never counts. What was seen is the set of keys Home last showed, kept in
/// <c>seen-findings.json</c>: hashes only.
/// </summary>
public static class FindingBadge
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 1;

    /// <summary>The keys of the findings Home shows open: not dismissed.</summary>
    public static IReadOnlySet<string> Open(IEnumerable<DoctorCheck> checks, Dismissals dismissals) =>
        checks.Where(c => c.IsFinding && dismissals.For(c) is null).Select(Dismissals.KeyOf).ToHashSet();

    /// <summary>How many of the open findings weren't among those Home last showed.</summary>
    public static int New(IReadOnlySet<string> open, IReadOnlySet<string> seen) => open.Count(k => !seen.Contains(k));

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string ToJson(IReadOnlySet<string> seen) => JsonSerializer.Serialize(new File(Version, [.. seen.Order(StringComparer.Ordinal)]), Json);

    /// <summary>The keys in a file, or none when it is missing, damaged or newer: every finding then counts as new, which costs a look, never a hidden one.</summary>
    public static IReadOnlySet<string> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new HashSet<string>();
        try
        {
            return JsonSerializer.Deserialize<File>(json, Json) is { V: Version, Keys: { } keys }
                ? keys.Where(k => !string.IsNullOrEmpty(k)).ToHashSet()
                : new HashSet<string>();
        }
        catch (JsonException)
        {
            return new HashSet<string>();
        }
    }

    sealed record File(int V, string[]? Keys);
}
