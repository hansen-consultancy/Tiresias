using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tiresias.Client;

/// <summary>A finding the user set aside, with why. <see cref="Name"/> is kept to list it; the key decides.</summary>
public sealed record Dismissal(string Key, string Name, string Reason, DateTimeOffset At);

/// <summary>
/// The findings the user dismissed. A finding is matched by <see cref="KeyOf"/>: the line, its fix
/// with that fix's inputs, its position and its <see cref="DoctorCheck.Subject"/>. So the same thing
/// isn't raised again, while one that comes back changed (another server, another variable, a new
/// key) is a new finding. Immutable;
/// the agent keeps it in <c>dismissals.json</c>.
/// </summary>
public sealed record Dismissals(IReadOnlyList<Dismissal> Items)
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 1;

    public static readonly Dismissals Empty = new([]);

    /// <summary>A finding's identity, hashed so the file holds no instruction text beyond the name.</summary>
    public static string KeyOf(DoctorCheck check) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(check.Subject is null
            ? $"{check.Name}\n{check.Fix?.Instruction}\n{check.Now}"
            : $"{check.Name}\n{check.Fix?.Instruction}\n{check.Now}\n{check.Subject}")));

    public Dismissal? For(DoctorCheck check)
    {
        var key = KeyOf(check);
        return Items.FirstOrDefault(d => d.Key == key);
    }

    /// <summary>Dismisses a finding, replacing an earlier reason for it. Anything else is not a finding and stays as it is.</summary>
    public Dismissals Dismiss(DoctorCheck check, string reason, DateTimeOffset now)
    {
        if (!check.IsFinding || string.IsNullOrWhiteSpace(reason))
            return this;
        var key = KeyOf(check);
        return new([.. Items.Where(d => d.Key != key), new Dismissal(key, check.Name, reason.Trim(), now)]);
    }

    public Dismissals Restore(string key) => new([.. Items.Where(d => d.Key != key)]);

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public string ToJson() => JsonSerializer.Serialize(new File(Version, [.. Items]), Json);

    /// <summary>
    /// The dismissals in a file, or none when it is missing, damaged or newer: a dismissal lost shows
    /// a finding again, which costs a click, never a hidden problem.
    /// </summary>
    public static Dismissals Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Empty;
        try
        {
            var file = JsonSerializer.Deserialize<File>(json, Json);
            return file is { V: Version, Items: { } items }
                ? new([.. items.Where(d => d is { Key.Length: > 0, Reason.Length: > 0 }).Select(d => d with { Name = d.Name ?? "" })])
                : Empty;
        }
        catch (JsonException)
        {
            return Empty;
        }
    }

    sealed record File(int V, Dismissal[]? Items);
}
