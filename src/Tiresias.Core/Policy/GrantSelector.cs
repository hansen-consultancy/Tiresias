using System.Text.RegularExpressions;

namespace Tiresias.Policy;

/// <summary>
/// An upstream reached through the broker, e.g. <c>llm</c> → https://llm.example.com. A service may hold
/// several credentials at different privilege levels (read, write, admin key); each is a
/// <see cref="Grant"/>, listed from least to most privileged.
/// </summary>
public sealed record Service(string Slug, Uri Upstream, IReadOnlyList<Grant> Grants);

/// <summary>
/// One credential of a service and the requests it may be used for.
/// </summary>
/// <param name="SecretSlug">Vault secret injected when this grant is chosen.</param>
/// <param name="RequiresElevation">The grant is usable only while an elevation for it is active (a fresh Hello prompt, time-boxed).</param>
/// <param name="IssuesLogins">
/// SQL Server only: the grant may be handed to an application as a temporary login for the lease
/// (<c>POST /sql/{instance}/{grant}/login</c>), not only used by the broker for one statement at a
/// time. Opt-in, because a handed-out login is no longer checked statement by statement.
/// </param>
public sealed record Grant(string Name, string SecretSlug, RequestRule Rule, bool RequiresElevation = false, bool IssuesLogins = false);

/// <summary>Which requests a grant covers. Deny patterns win over allow patterns.</summary>
/// <param name="Methods">Upper-case HTTP methods. Empty allows none.</param>
/// <param name="Allow">Anchored regexes over the path and query (<c>/v1/models?x=1</c>). Empty allows none.</param>
public sealed record RequestRule(
    IReadOnlySet<string> Methods,
    IReadOnlyList<Regex> Allow,
    IReadOnlyList<Regex>? Deny = null,
    long? MaxBodyBytes = null)
{
    public bool Covers(BrokeredRequest request) =>
        Methods.Contains(request.Method)
        && (MaxBodyBytes is null || request.BodyBytes <= MaxBodyBytes)
        && Allow.Any(r => r.IsMatch(request.PathAndQuery))
        && !(Deny ?? []).Any(r => r.IsMatch(request.PathAndQuery));
}

public sealed record BrokeredRequest(string Method, string PathAndQuery, long BodyBytes);

public enum DenyReason
{
    None,
    /// <summary>The path uses an encoding or traversal trick; refused before any rule sees it.</summary>
    SuspiciousPath,
    /// <summary>No grant up to the placeholder's ceiling covers the request.</summary>
    NotCovered,
    /// <summary>A grant covers it, but needs an elevation that isn't active. <see cref="GrantDecision.ElevationNeeded"/> names it.</summary>
    ElevationRequired,
}

public sealed record GrantDecision(Grant? Grant, DenyReason Reason, string? ElevationNeeded = null)
{
    public bool Allowed => Grant is not null;
}

/// <summary>
/// Picks the credential for one request: the <b>least privileged</b> grant that covers it, never
/// above the placeholder's ceiling. A consumer therefore keeps one placeholder per service and
/// still never sends a write or admin key on a request a read key could serve.
/// </summary>
public static class GrantSelector
{
    /// <param name="ceiling">Most privileged grant the placeholder may use; <c>null</c> = every grant.</param>
    /// <param name="activeElevations">Names of this service's grants whose elevation is active now.</param>
    public static GrantDecision Select(Service service, BrokeredRequest request, string? ceiling, IReadOnlySet<string> activeElevations)
    {
        if (!PathGuard.IsClean(request.PathAndQuery))
            return new(null, DenyReason.SuspiciousPath);

        var method = request.Method.ToUpperInvariant();
        var normalized = request with { Method = method };

        string? elevationNeeded = null;
        foreach (var grant in service.Grants)
        {
            if (grant.Rule.Covers(normalized))
            {
                if (!grant.RequiresElevation || activeElevations.Contains(grant.Name))
                    return new(grant, DenyReason.None);
                elevationNeeded ??= grant.Name;
            }

            if (grant.Name == ceiling)
                break;
        }

        return elevationNeeded is null
            ? new(null, DenyReason.NotCovered)
            : new(null, DenyReason.ElevationRequired, elevationNeeded);
    }
}

/// <summary>
/// Refuses paths that mean something different to the regex than to the upstream. Rejecting beats
/// normalising: a normaliser that disagrees with the upstream's is how URL allow-lists get bypassed.
/// </summary>
public static class PathGuard
{
    static readonly string[] EncodedTricks = ["%2e", "%2f", "%5c", "%25", "%00"];

    public static bool IsClean(string pathAndQuery)
    {
        if (pathAndQuery.Length == 0 || pathAndQuery[0] != '/')
            return false;

        var queryStart = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
        var path = queryStart < 0 ? pathAndQuery : pathAndQuery[..queryStart];

        if (path.Contains('\\', StringComparison.Ordinal) || path.Contains("//", StringComparison.Ordinal) || path.Any(char.IsControl))
            return false;
        if (EncodedTricks.Any(t => path.Contains(t, StringComparison.OrdinalIgnoreCase)))
            return false;

        return !path.Split('/').Any(segment => segment is "." or "..");
    }
}
