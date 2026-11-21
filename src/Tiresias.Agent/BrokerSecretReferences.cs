using Tiresias.Access;
using Tiresias.UserSecrets;

namespace Tiresias.Agent;

/// <summary>
/// Fetches a reference's value with a placeholder for the service, capped at the grant.
/// <list type="bullet">
/// <item><c>tiresias:sql/{service}/{grant}</c>: the placeholder is traded at once for the lease's
/// temporary login and revoked, so only the login remains, and it is dropped when the lease ends.</item>
/// <item><c>tiresias:raven/{service}</c>: the placeholder is the value, inside the URL a RavenDB
/// client is given (<c>http://127.0.0.1:7781/raven/{service}/tirph_…</c>), and dies with the lease.</item>
/// </list>
/// </summary>
/// <param name="keys">The agent's unlocked state, whose Hello wrapper signs each placeholder's approval.</param>
public sealed class BrokerSecretReferences(AgentKeys keys) : ISecretReferenceResolver
{
    public async Task<ResolvedSecret> ResolveAsync(SecretReference reference, string? caller, string userSecretsId, CancellationToken ct)
    {
        if (KeyringStore.Broker is not { } broker)
            throw new InvalidOperationException($"{reference}: this PC isn't enrolled with a broker.");
        if (KeyringStore.Tenant is { Solo: true } && !await SoloBroker.ReachableAsync())
            throw new InvalidOperationException($"{reference}: the solo broker isn't running.");

        if (keys.Hello is not { } hello)
            throw new InvalidOperationException($"{reference}: Tiresias is locked.");

        using var client = BrokerClient.For(broker);
        var response = await client.PostAsync("/placeholder", Approvals.Mint(hello,
            new AccessRequest($"usersecrets:{userSecretsId}", caller, reference.Service, reference.Grant, $"{userSecretsId} user secrets", Consent.MaxDuration)));
        if (response is not { Ok: true, Body: { } body } || !body.TryGetProperty("token", out var token) || token.GetString() is not { } placeholder)
            throw new InvalidOperationException($"{reference}: {response.Describe()}");
        if (reference.Kind == SecretReference.Raven)
            return new($"{PlaceholderMinter.Endpoint.GetLeftPart(UriPartial.Authority)}/raven/{Uri.EscapeDataString(reference.Service)}/{placeholder}",
                body.TryGetProperty("expiresAt", out var expires) && expires.TryGetDateTimeOffset(out var at) ? at : null);
        try
        {
            var (connectionString, expiresAt) = await SqlLogin.RequestAsync(reference.Service, reference.Grant!, placeholder, ct);
            return new(connectionString, expiresAt);
        }
        finally
        {
            await client.PostAsync("/placeholder/revoke", new { token = placeholder });
        }
    }
}
