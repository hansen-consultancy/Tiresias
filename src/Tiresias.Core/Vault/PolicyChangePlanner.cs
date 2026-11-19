using Tiresias.Policy;

namespace Tiresias.Vault;

/// <summary>
/// A change to a vault's services, as the user approves it.
/// </summary>
/// <param name="Set">Services added, or replacing the one with the same slug.</param>
/// <param name="Remove">Slugs of services removed; their secrets stay.</param>
/// <param name="Next">The vault with the change made, secrets not yet rebound.</param>
/// <param name="Lines">What changes, for the approval dialog: services, upstreams, grants and their rules. Never a value.</param>
/// <param name="Rebind">
/// Secrets whose approved policy must become their policy in <see cref="Next"/>: those whose policy
/// the change alters, and those of the services set that aren't approved for it yet (unbound, or
/// left behind by an unapproved edit).
/// </param>
public sealed record PolicyChange(IReadOnlyList<Service> Set, IReadOnlyList<string> Remove, VaultDocument Next, IReadOnlyList<string> Lines, IReadOnlyList<string> Rebind)
{
    /// <summary>Nothing to approve: saving would write the vault as it is.</summary>
    public bool IsEmpty => Lines.Count == 0 && Rebind.Count == 0;
}

/// <summary>Plans a change to a vault's services: what the user is shown, and which secrets their approval rebinds.</summary>
public static class PolicyChangePlanner
{
    /// <exception cref="InvalidOperationException">A service set uses a secret that isn't in the vault.</exception>
    public static PolicyChange Plan(VaultDocument current, IReadOnlyList<Service> set, IReadOnlyList<string> remove)
    {
        if (set.SelectMany(s => s.Grants).FirstOrDefault(g => current.FindSecret(g.SecretSlug) is null) is { } orphan)
            throw new InvalidOperationException($"Secret {orphan.SecretSlug} isn't in the vault; add it first.");

        var setSlugs = set.Select(s => s.Slug).ToHashSet(StringComparer.Ordinal);
        var services = current.Services
            .Where(s => !remove.Contains(s.Slug) && !setSlugs.Contains(s.Slug))
            .Concat(set)
            .ToArray();
        var next = current with { Services = services };

        var setSecrets = set.SelectMany(s => s.Grants).Select(g => g.SecretSlug).ToHashSet(StringComparer.Ordinal);
        var rebind = next.Secrets
            .Where(secret =>
            {
                var policy = PolicyBinding.Hash(next, secret.Slug);
                var changed = !policy.AsSpan().SequenceEqual(PolicyBinding.Hash(current, secret.Slug));
                return (changed || setSecrets.Contains(secret.Slug)) && !Approved(secret, policy);
            })
            .Select(s => s.Slug)
            .ToArray();

        var lines = new List<string>();
        foreach (var slug in remove.Where(slug => current.FindService(slug) is not null && !setSlugs.Contains(slug)))
        {
            lines.Add($"Remove service {slug}");
            lines.AddRange(Describe(current.FindService(slug)!).Select(line => $"  - {line}"));
        }
        foreach (var service in set)
        {
            var after = Describe(service);
            if (current.FindService(service.Slug) is not { } existing)
            {
                lines.Add($"Add service {service.Slug}");
                lines.AddRange(after.Select(line => $"  + {line}"));
                continue;
            }
            var before = Describe(existing);
            var removed = before.Except(after).ToArray();
            var added = after.Except(before).ToArray();
            if (removed.Length + added.Length > 0)
            {
                lines.Add($"Change service {service.Slug}");
                lines.AddRange(removed.Select(line => $"  - {line}"));
                lines.AddRange(added.Select(line => $"  + {line}"));
            }
            else if (service.Grants.Any(g => rebind.Contains(g.SecretSlug)))
            {
                lines.Add($"Approve service {service.Slug} as it is");
                lines.AddRange(after.Select(line => $"    {line}"));
            }
        }
        return new(set, remove, next, lines, rebind);
    }

    static bool Approved(SealedSecret secret, byte[] policy) =>
        secret.PolicyHash is { } approved && approved.AsSpan().SequenceEqual(policy);

    /// <summary>A service as lines a diff compares: its upstream, then each grant with its position (ceilings are positional).</summary>
    static IReadOnlyList<string> Describe(Service service) =>
    [
        $"upstream {service.Upstream.OriginalString}",
        .. service.Grants.Select((grant, index) => $"grant {index + 1}. {grant.Name}: secret {grant.SecretSlug}, {Describe(grant.Rule)}"
            + (grant.RequiresElevation ? ", needs elevation" : "")
            + (grant.IssuesLogins ? ", issues logins" : "")),
    ];

    static string Describe(RequestRule rule) =>
        $"{string.Join(",", rule.Methods.Order(StringComparer.Ordinal))} {string.Join(" ", rule.Allow)}"
        + (rule.Deny is { Count: > 0 } deny ? $", deny {string.Join(" ", deny)}" : "")
        + (rule.MaxBodyBytes is { } max ? $", body up to {max} bytes" : "");
}
