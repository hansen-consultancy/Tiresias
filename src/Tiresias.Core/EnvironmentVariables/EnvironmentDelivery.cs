using Tiresias.Access;
using Tiresias.Client;

namespace Tiresias.EnvironmentVariables;

/// <summary>What a process got: the variables to set, and why any were left out (never a value).</summary>
public sealed record Delivery(IReadOnlyDictionary<string, string> Variables, IReadOnlyList<string> Problems);

/// <summary>A minted placeholder and when the broker lets it expire (it caps that at the lease's end), or why there is none.</summary>
public sealed record MintedPlaceholder(string? Token, string? Problem = null, DateTimeOffset? ExpiresAt = null);

/// <summary>
/// Turns resolved sealed variables into what a process gets. A variable delivered as a placeholder
/// gets one from <c>mint</c>, plus the forwarder's URL for its service in its base-URL variable;
/// the rest get their values. A placeholder that can't be minted leaves that variable out with a
/// reason: it never falls back to the real value.
/// </summary>
public static class EnvironmentDelivery
{
    public static async Task<Delivery> DeliverAsync(SealedEnvironment environment, IEnumerable<SealedVariable> variables, Uri forwarder,
        Func<EnvironmentPlaceholder, CancellationToken, Task<MintedPlaceholder>> mint, CancellationToken ct)
    {
        var given = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var problems = new List<string>();
        foreach (var variable in variables)
        {
            if (environment.PlaceholderFor(variable.Name) is not { } placeholder)
            {
                given[variable.Name] = variable.Value;
                continue;
            }
            var minted = await mint(placeholder, ct);
            if (minted.Token is not { } token)
            {
                problems.Add($"{variable.Name} was left out: no placeholder for {placeholder.Service} ({minted.Problem ?? "the broker refused"}).");
                continue;
            }
            given[variable.Name] = token;
            given[placeholder.BaseUrlVariable] = ExecPlan.ServiceUrl(placeholder.Service, forwarder);
        }
        return new(given, problems);
    }

    /// <summary>A name as consent dialogs list it: a placeholder delivery says so, and for which service.</summary>
    public static string Describe(SealedEnvironment environment, string name) =>
        environment.PlaceholderFor(name) is { } placeholder ? $"{name} (a placeholder for {placeholder.Service})" : name;

    /// <summary>The placeholders among values a process was given, to revoke when it is done.</summary>
    public static IEnumerable<string> Placeholders(IEnumerable<string> values) =>
        values.Where(v => v.StartsWith(PlaceholderToken.Prefix, StringComparison.Ordinal));
}
