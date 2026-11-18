using Tiresias.Access;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Agent;

/// <summary>
/// Mints and revokes the placeholders <see cref="EnvironmentDelivery"/> hands out, through this
/// device's broker. The app keeps one per terminal and variable (<see cref="ShellPlaceholders"/>);
/// <c>tir run</c> mints for its one command and revokes when it exits.
/// </summary>
public static class PlaceholderMinter
{
    /// <summary>The forwarder, which relays to a remote broker. A solo broker is called directly.</summary>
    static readonly Uri Forwarder = new("http://127.0.0.1:7781");

    /// <summary>Where a process sends its placeholders.</summary>
    public static Uri Endpoint => KeyringStore.Tenant is { Solo: true } ? SoloBroker.Url : Forwarder;

    /// <param name="consumer">Who the placeholder is for, as the audit log shows it, e.g. <c>terminal:pwsh</c>.</param>
    /// <param name="observed">The process the app identified, which the requester can't choose.</param>
    public static async Task<MintedPlaceholder> MintAsync(EnvironmentPlaceholder placeholder, string consumer, string? observed)
    {
        try
        {
            if (KeyringStore.Broker is not { } broker)
                return new(null, "this PC isn't enrolled with a broker");
            if (KeyringStore.Tenant is { Solo: true } && !await SoloBroker.ReachableAsync())
                return new(null, "the solo broker isn't running");
            using var client = BrokerClient.For(broker);
            var response = await client.PostAsync("/placeholder",
                new AccessRequest(consumer, observed, placeholder.Service, null, $"{placeholder.Variable} in the environment", Consent.MaxDuration));
            return response is { Ok: true, Body: { } body } && body.TryGetProperty("token", out var token) && token.GetString() is { } value
                ? new(value)
                : new(null, response.Describe());
        }
        catch (Exception e) when (e is HttpRequestException or IOException or InvalidOperationException or TaskCanceledException)
        {
            return new(null, e.Message);
        }
    }

    /// <summary>Best effort: a placeholder that can't be revoked still expires, and dies with the broker's lease.</summary>
    public static async Task RevokeAsync(IEnumerable<string> tokens)
    {
        var list = tokens.ToArray();
        if (list.Length == 0 || KeyringStore.Broker is not { } broker)
            return;
        try
        {
            using var client = BrokerClient.For(broker);
            foreach (var token in list)
                await client.PostAsync("/placeholder/revoke", new { token });
        }
        catch (Exception e) when (e is HttpRequestException or IOException or InvalidOperationException or TaskCanceledException)
        {
        }
    }
}
