using System.Text.Json;
using System.Text.Json.Serialization;
using Tiresias.Audit;

namespace Tiresias.App.Logic;

public enum ActivitySource
{
    /// <summary>The agent's own log: user-secrets consent decisions.</summary>
    UserSecrets,
    /// <summary>The solo broker's audit log: leases, placeholders, requests.</summary>
    Broker,
}

public enum ActivityOutcome
{
    All,
    Allowed,
    Denied,
}

public enum ActivityPeriod
{
    Today,
    Week,
    All,
}

/// <summary>One audit line as the activity window shows it. Holds what the audit holds: never a value.</summary>
public sealed record ActivityEntry(
    DateTimeOffset Time,
    ActivitySource Source,
    AuditKind Kind,
    string? Consumer,
    string? Service,
    string? Process,
    string? Reason,
    string? Method,
    string? Path,
    int? Status);

public sealed record ActivityFilter(string? Text = null, ActivityOutcome Outcome = ActivityOutcome.All, ActivitySource? Source = null,
    ActivityPeriod Period = ActivityPeriod.Week);

/// <summary>Reads the local audit logs and filters them for the activity window.</summary>
public static class ActivityQuery
{
    /// <summary>The most the window lists; older entries stay in the files.</summary>
    public const int Limit = 2000;

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    /// <returns><c>null</c> for a line that isn't an audit record (a torn last line, a newer format).</returns>
    public static ActivityEntry? Parse(string line, ActivitySource source)
    {
        try
        {
            var r = JsonSerializer.Deserialize<Line>(line, Json);
            return r is null ? null : new(r.Time, source, r.Kind, r.Consumer, r.Service, r.Process, r.Reason, r.Method, r.Path, r.Status);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static IReadOnlyList<ActivityEntry> Filter(IEnumerable<ActivityEntry> entries, ActivityFilter filter, DateTimeOffset now)
    {
        var since = filter.Period switch
        {
            ActivityPeriod.Today => new DateTimeOffset(now.ToLocalTime().Date, now.ToLocalTime().Offset),
            ActivityPeriod.Week => now.AddDays(-7),
            _ => DateTimeOffset.MinValue,
        };
        var text = filter.Text?.Trim();
        return entries
            .Where(e => e.Time >= since)
            .Where(e => filter.Source is null || e.Source == filter.Source)
            .Where(e => filter.Outcome switch
            {
                ActivityOutcome.Allowed => !IsDenial(e.Kind),
                ActivityOutcome.Denied => IsDenial(e.Kind),
                _ => true,
            })
            .Where(e => string.IsNullOrEmpty(text) || Fields(e).Any(f => f?.Contains(text, StringComparison.OrdinalIgnoreCase) == true))
            .OrderByDescending(e => e.Time)
            .Take(Limit)
            .ToArray();
    }

    public static bool IsDenial(AuditKind kind) => kind is AuditKind.Deny or AuditKind.TrustRejected;

    /// <summary>The kind in words.</summary>
    public static Phrase Describe(AuditKind kind) => kind switch
    {
        AuditKind.LeaseBegin => new("Kind_LeaseBegin"),
        AuditKind.LeaseEnd => new("Kind_LeaseEnd"),
        AuditKind.Mint => new("Kind_Mint"),
        AuditKind.Allow => new("Kind_Allow"),
        AuditKind.Deny => new("Kind_Deny"),
        AuditKind.Elevate => new("Kind_Elevate"),
        AuditKind.TrustLink => new("Kind_TrustLink"),
        AuditKind.TrustRejected => new("Kind_TrustRejected"),
        AuditKind.BreakGlass => new("Kind_BreakGlass"),
        AuditKind.Token => new("Kind_Token"),
        AuditKind.PlaceholderRevoked => new("Kind_PlaceholderRevoked"),
        AuditKind.Anchor => new("Kind_Anchor"),
        _ => new("Kind_Other", kind.ToString()),
    };

    static IEnumerable<string?> Fields(ActivityEntry e) => [e.Consumer, e.Service, e.Process, e.Reason, e.Method, e.Path, e.Kind.ToString()];

    sealed record Line(DateTimeOffset Time, AuditKind Kind, string? Consumer, string? Service, string? Process, string? Reason, string? Method,
        string? Path, int? Status);
}
