using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.Client;

/// <summary>A finding the user set aside, with why. <see cref="Name"/> is kept to list it; the key decides.</summary>
/// <param name="Signer">For a finding about an <see cref="DoctorCheck.Item"/>: the publisher key it had, which must not change.</param>
/// <param name="Accepted">For a finding about an <see cref="DoctorCheck.Item"/>: the reasons accepted; any other brings it back.</param>
public sealed record Dismissal(string Key, string Name, string Reason, DateTimeOffset At, string? Signer = null, IReadOnlyList<string>? Accepted = null)
{
    /// <summary>Set when the finding is hidden by trust in its publisher rather than by a dismissal of its own. Never stored.</summary>
    [JsonIgnore]
    public TrustedPublisher? Trusted { get; init; }
}

/// <summary>
/// The findings the user dismissed and the publishers they trust. A finding is matched by
/// <see cref="KeyOf"/>: the line, its fix with that fix's inputs, its position and its
/// <see cref="DoctorCheck.Subject"/>. So the same thing isn't raised again, while one that comes back
/// changed (another server, another variable, a new key) is a new finding. A finding about an
/// installed <see cref="DoctorCheck.Item"/> is matched by the item instead, so an update keeps it
/// dismissed, and comes back when its signer changes or a reason the user didn't accept appears.
/// Immutable; the agent keeps it in <c>dismissals.json</c>.
/// </summary>
public sealed record Dismissals(IReadOnlyList<Dismissal> Items, IReadOnlyList<TrustedPublisher> Publishers)
{
    /// <summary>The file format; a change bumps it. Version 1 (no publishers, no items) is read forward.</summary>
    public const int Version = 2;

    public Dismissals(IReadOnlyList<Dismissal> items)
        : this(items, [])
    {
    }

    public static readonly Dismissals Empty = new([], []);

    /// <summary>A finding's identity, hashed so the file holds no instruction text beyond the name.</summary>
    public static string KeyOf(DoctorCheck check) => check.Item is { } item ? Hash($"item\n{item}") : LineKey(check);

    /// <summary>The key version 1 gave every finding, and still gives one without an item.</summary>
    static string LineKey(DoctorCheck check) => Hash(check.Subject is null
        ? $"{check.Name}\n{check.Fix?.Instruction}\n{check.Now}"
        : $"{check.Name}\n{check.Fix?.Instruction}\n{check.Now}\n{check.Subject}");

    static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>What hides the finding: its own dismissal, else trust in its publisher; <c>null</c> when it shows.</summary>
    public Dismissal? For(DoctorCheck check)
    {
        if (check.Item is null)
        {
            var key = LineKey(check);
            return Items.FirstOrDefault(d => d.Key == key);
        }
        var itemKey = KeyOf(check);
        var legacy = LineKey(check);
        return Items.FirstOrDefault(d => d.Key == itemKey && d.Signer == check.Signer?.Key
                   && (check.Reasons ?? []).All(r => d.Accepted?.Contains(r, StringComparer.Ordinal) == true))
            ?? Items.FirstOrDefault(d => d.Accepted is null && d.Key == legacy)
            ?? (TrustedFor(check) is { } trusted
                ? new Dismissal(itemKey, check.Name, $"you trust {trusted.Name}", trusted.At) { Trusted = trusted }
                : null);
    }

    /// <summary>The trusted publisher that hides the finding: one whose key is the finding's signer, for a finding trust may hide.</summary>
    public TrustedPublisher? TrustedFor(DoctorCheck check) =>
        check is { TrustHides: true, Signer: { } signer } ? Publishers.FirstOrDefault(p => p.Key == signer.Key) : null;

    public bool Trusts(Publisher publisher) => Publishers.Any(p => p.Key == publisher.Key);

    /// <summary>Dismisses a finding, replacing an earlier reason for it. Anything else is not a finding and stays as it is.</summary>
    public Dismissals Dismiss(DoctorCheck check, string reason, DateTimeOffset now)
    {
        if (!check.IsFinding || string.IsNullOrWhiteSpace(reason))
            return this;
        var key = KeyOf(check);
        var dismissal = check.Item is null
            ? new Dismissal(key, check.Name, reason.Trim(), now)
            : new Dismissal(key, check.Name, reason.Trim(), now, check.Signer?.Key, [.. check.Reasons ?? []]);
        return this with { Items = [.. Items.Where(d => d.Key != key), dismissal] };
    }

    public Dismissals Restore(string key) => this with { Items = [.. Items.Where(d => d.Key != key)] };

    /// <summary>Trusts a publisher: the findings trust may hide about what it signed stop showing, now and after updates.</summary>
    public Dismissals Trust(Publisher publisher, DateTimeOffset now) =>
        Trusts(publisher) ? this : this with { Publishers = [.. Publishers, new(publisher.Key, publisher.Name, now)] };

    /// <summary>Stops trusting a publisher; what its trust hid shows again, unless dismissed on its own.</summary>
    public Dismissals Distrust(string key) => this with { Publishers = [.. Publishers.Where(p => p.Key != key)] };

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(new File(Version, [.. Items], [.. Publishers]), Json);

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
            return file is { V: 1 or Version, Items: { } items }
                ? new([.. items.Where(d => d is { Key.Length: > 0, Reason.Length: > 0 }).Select(d => d with { Name = d.Name ?? "" })],
                    [.. (file.Publishers ?? []).Where(p => p is { Key.Length: > 0 }).Select(p => p with { Name = p.Name ?? p.Key })])
                : Empty;
        }
        catch (JsonException)
        {
            return Empty;
        }
    }

    sealed record File(int V, Dismissal[]? Items, TrustedPublisher[]? Publishers = null);
}
