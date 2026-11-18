using Tiresias.Access;
using Tiresias.UserSecrets;

namespace Tiresias.Agent;

/// <summary>
/// Fetches a <c>tiresias:sql/{service}/{grant}</c> value: a placeholder for the service capped at the
/// grant, traded at once for the lease's temporary login and revoked, so only the login remains,
/// and it is dropped when the lease ends.
/// </summary>
public sealed class BrokerSecretReferences : ISecretReferenceResolver
{
    public async Task<ResolvedSecret> ResolveAsync(SecretReference reference, string? caller, string userSecretsId, CancellationToken ct)
    {
        if (KeyringStore.Broker is not { } broker)
            throw new InvalidOperationException($"{reference}: this PC isn't enrolled with a broker.");
        if (KeyringStore.Tenant is { Solo: true } && !await SoloBroker.ReachableAsync())
            throw new InvalidOperationException($"{reference}: the solo broker isn't running.");

        using var client = BrokerClient.For(broker);
        var response = await client.PostAsync("/placeholder",
            new AccessRequest($"usersecrets:{userSecretsId}", caller, reference.Service, reference.Grant, $"{userSecretsId} user secrets", Consent.MaxDuration));
        if (response is not { Ok: true, Body: { } body } || !body.TryGetProperty("token", out var token) || token.GetString() is not { } placeholder)
            throw new InvalidOperationException($"{reference}: {response.Describe()}");
        try
        {
            var (connectionString, expiresAt) = await SqlLogin.RequestAsync(reference.Service, reference.Grant, placeholder, ct);
            return new(connectionString, expiresAt);
        }
        finally
        {
            await client.PostAsync("/placeholder/revoke", new { token = placeholder });
        }
    }
}
