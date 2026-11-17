using Tiresias.Policy;

namespace Tiresias.Access;

/// <summary>
/// What a consumer asks for before it gets a placeholder, and what the consent prompt shows the user.
/// before the Hello prompt. Nothing is minted without one, and the approved request is stored with
/// the placeholder, so every audit record can say who asked, for what, and why.
/// </summary>
/// <param name="Consumer">Name the requester gives itself, e.g. <c>claude:recursing-greider</c> or <c>script:nightly-export</c>.</param>
/// <param name="ObservedProcess">What the forwarder saw on the loopback connection (image path + PID), which the requester can't choose. Shown next to the claim so a mismatch is visible.</param>
/// <param name="Ceiling">Most privileged grant allowed, e.g. <c>read</c> for a script that must never write. <c>null</c> = every grant (still subject to elevation).</param>
/// <param name="Purpose">Free text, required: what the access is for.</param>
public sealed record AccessRequest(
    string Consumer,
    string? ObservedProcess,
    string ServiceSlug,
    string? Ceiling,
    string Purpose,
    TimeSpan Duration);

public static class Consent
{
    public static readonly TimeSpan MaxDuration = TimeSpan.FromHours(10);

    /// <summary>Problems that make a request unapprovable. An empty list means it can be shown for consent.</summary>
    public static IReadOnlyList<string> Validate(AccessRequest request, Service service)
    {
        var problems = new List<string>();
        if (string.IsNullOrWhiteSpace(request.Consumer))
            problems.Add("No consumer name.");
        if (string.IsNullOrWhiteSpace(request.Purpose))
            problems.Add("No purpose given.");
        if (request.Duration <= TimeSpan.Zero || request.Duration > MaxDuration)
            problems.Add($"Duration must be between 0 and {MaxDuration.TotalHours:0} h.");
        if (request.Ceiling is not null && service.Grants.All(g => g.Name != request.Ceiling))
            problems.Add($"Service '{service.Slug}' has no grant '{request.Ceiling}'.");
        return problems;
    }

    /// <summary>
    /// The lines the consent prompt shows, in order. Plain text so the Windows prompt, the CLI and
    /// the audit log all say the same thing. The grants listed are exactly the ones the placeholder
    /// will be able to reach, with the ones that still need elevation marked.
    /// </summary>
    public static IReadOnlyList<string> Describe(AccessRequest request, Service service)
    {
        var reachable = Reachable(service, request.Ceiling);
        return
        [
            $"Requested by: {request.Consumer}",
            $"Process:      {request.ObservedProcess ?? "unknown (not observed)"}",
            $"Service:      {service.Slug} ({service.Upstream})",
            $"Access up to: {request.Ceiling ?? "all grants"}",
            $"Grants:       {string.Join(", ", reachable.Select(g => g.RequiresElevation ? $"{g.Name} (needs elevation)" : g.Name))}",
            $"Purpose:      {request.Purpose}",
            $"For:          {FormatDuration(request.Duration)}",
        ];
    }

    /// <summary>The grants a placeholder with this ceiling can ever use, least privileged first.</summary>
    public static IReadOnlyList<Grant> Reachable(Service service, string? ceiling)
    {
        if (ceiling is null)
            return service.Grants;
        var index = service.Grants.ToList().FindIndex(g => g.Name == ceiling);
        return index < 0 ? [] : service.Grants.Take(index + 1).ToArray();
    }

    static string FormatDuration(TimeSpan d) =>
        d.TotalHours >= 1 ? $"{d.TotalHours:0.#} h" : $"{d.TotalMinutes:0} min";
}
