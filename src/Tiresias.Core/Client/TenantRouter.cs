namespace Tiresias.Client;

/// <summary>A broker the Keyring is enrolled with, by the services its vault holds.</summary>
public sealed record TenantServices(string Name, IReadOnlySet<string> Services);

/// <param name="Tenant">The tenant to use, or <c>null</c> with <see cref="Error"/> saying why none could be picked.</param>
public sealed record TenantChoice(string? Tenant, string? Error);

/// <summary>
/// Picks the broker a command talks to when the Keyring is enrolled with several (one per tenant:
/// personal, customer). Never guesses between two: a credential sent to the wrong tenant's broker
/// is a cross-tenant leak, so ambiguity is an error naming the choices.
/// </summary>
public static class TenantRouter
{
    /// <param name="service">The service the command is about, when it is about one.</param>
    /// <param name="requested">The <c>--tenant</c> option, when given.</param>
    public static TenantChoice Resolve(IReadOnlyList<TenantServices> tenants, string? service, string? requested)
    {
        if (tenants.Count == 0)
            return new(null, "Not enrolled with any broker. Run tir enroll.");

        if (requested is not null)
        {
            if (tenants.FirstOrDefault(t => t.Name == requested) is not { } chosen)
                return new(null, $"No tenant '{requested}'. Known: {Names(tenants)}.");
            return service is null || chosen.Services.Contains(service)
                ? new(chosen.Name, null)
                : new(null, $"Tenant '{requested}' has no service '{service}'.");
        }

        if (service is not null)
        {
            var holders = tenants.Where(t => t.Services.Contains(service)).ToArray();
            if (holders.Length == 1)
                return new(holders[0].Name, null);
            if (holders.Length > 1)
                return new(null, $"Service '{service}' is in several tenants ({Names(holders)}); pass --tenant.");
        }

        return tenants.Count == 1
            ? new(tenants[0].Name, null)
            : new(null, service is null
                ? $"Enrolled with several tenants ({Names(tenants)}); pass --tenant."
                : $"No tenant has a service '{service}'. Known tenants: {Names(tenants)}.");
    }

    static string Names(IEnumerable<TenantServices> tenants) => string.Join(", ", tenants.Select(t => t.Name));
}
