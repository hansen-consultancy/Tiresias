using System.Net;
using System.Text.Json;
using NSec.Cryptography;
using Tiresias.Client;
using Tiresias.Crypto;
using Tiresias.Transport;
using Tiresias.Trust;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>What an unlock did. <see cref="Notes"/> are per-secret remarks (a secret this Hello credential can't open).</summary>
public sealed record UnlockResult(bool Ok, string Message, IReadOnlyList<string> Accepted, IReadOnlyList<string> Rejected, IReadOnlyList<string> Notes);

/// <summary>
/// Opening and ending the workday lease with the selected tenant's broker. The CLI and the tray app
/// both call these, so the two never disagree about how a lease is opened.
/// </summary>
public static class LeaseControl
{
    /// <summary>
    /// Opens a lease and seals the DEKs of <paramref name="slugs"/> (default: every secret with a
    /// Hello wrap) to it. <paramref name="hello"/> is the caller's open Hello wrapper, so an app that
    /// already holds one costs no second prompt.
    /// </summary>
    public static async Task<UnlockResult> UnlockAsync(HelloKeyWrapper hello, IReadOnlyList<string>? slugs = null)
    {
        var broker = KeyringStore.RequireBroker();
        var settings = KeyringStore.Settings;
        var vault = VaultFile.Load(settings.VaultPath);
        slugs ??= vault.Secrets.Where(s => s.WrappedDeks.ContainsKey("hello")).Select(s => s.Slug).ToArray();
        var secrets = slugs.Select(s => vault.FindSecret(s) ?? throw new InvalidOperationException($"No secret '{s}' in {settings.VaultPath}.")).ToArray();

        var notes = new List<string>();
        using var client = BrokerClient.For(broker);
        if (await CheckTrustChainAsync(client, broker, settings) is { } untrusted)
            return Failed($"{untrusted} Nothing was sealed.");
        var begin = await client.PostAsync("/lease/begin");
        if (!begin.Ok || begin.Body is not { } body)
            return Failed($"Lease not opened: {begin.Describe()}");

        var offer = new LeaseOffer(
            body.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(body.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(body.GetProperty("hardCapAt").GetInt64()));
        var identity = PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(broker.IdentityKey), KeyBlobFormat.RawPublicKey);
        if (!offer.Verify(identity, Convert.FromBase64String(body.GetProperty("signature").GetString()!)))
            return Failed("The lease offer is not signed by the pinned broker identity. Nothing was sealed.");

        var sealedDeks = new Dictionary<string, byte[]>();
        foreach (var secret in secrets)
        {
            var dek = SecretEnvelope.UnwrapDek(secret, hello);
            if (dek is null)
            {
                notes.Add($"{secret.Slug}: this Hello credential can't open it, skipped.");
                continue;
            }
            try
            {
                sealedDeks[secret.Slug] = SealedBox.Seal(offer.LeaseKey, dek, LeaseOffer.DekContext(offer.LeaseId, secret.Slug));
            }
            finally
            {
                Array.Clear(dek);
            }
        }

        var seal = await client.PostAsync("/lease/seal", new { offer.LeaseId, deks = sealedDeks });
        if (!seal.Ok || seal.Body is not { } result)
            return Failed($"DEKs not accepted: {seal.Describe()}");

        KeyringStore.Lease = new(offer.LeaseId, offer.HardCapAt);
        return new(true, $"Lease {offer.LeaseId} open until {offer.HardCapAt.ToLocalTime():HH:mm}.",
            Strings(result.GetProperty("accepted")), Strings(result.GetProperty("rejected")), notes);

        UnlockResult Failed(string message) => new(false, message, [], [], notes);
    }

    /// <summary>Ends the lease on the broker and forgets it here, whatever the broker answers.</summary>
    /// <returns>The broker's refusal, or <c>null</c> when it ended.</returns>
    public static async Task<string?> LockAsync()
    {
        using var client = BrokerClient.For(KeyringStore.RequireBroker());
        var end = await client.PostAsync("/lease/end");
        KeyringStore.Lease = null;
        return end.Ok ? null : end.Describe();
    }

    /// <summary>Asks the broker whether the remembered lease still runs, forgetting it when not.</summary>
    /// <returns>The lease, or <c>null</c> with the reason it is gone.</returns>
    public static async Task<(OpenLease? Lease, string? Ended)> CheckAsync()
    {
        if (KeyringStore.Lease is not { } lease || KeyringStore.Broker is not { } broker)
            return (null, null);
        using var client = BrokerClient.For(broker);
        var heartbeat = await client.PostAsync("/lease/heartbeat", new { lease.LeaseId });
        if (heartbeat.Ok)
            return (lease, null);
        KeyringStore.Lease = null;
        return (null, heartbeat.Describe());
    }

    /// <summary>
    /// When the tenant was enrolled with a genesis hash, refuses a broker whose trust chain doesn't
    /// verify per <see cref="BrokerTrust"/>, and remembers the head it accepts so the next unlock
    /// catches a rollback. Returns the reason to refuse, or null.
    /// </summary>
    static async Task<string?> CheckTrustChainAsync(BrokerClient client, BrokerPin broker, KeyringSettings settings)
    {
        if (KeyringStore.Tenant?.GenesisHash is not { } genesis)
            return null;
        var (status, body) = await client.GetAsync("/trust/chain");
        if (status != HttpStatusCode.OK)
            return $"This tenant pins a trust chain but the broker served none ({(int)status}).";
        var result = BrokerTrust.Evaluate(TrustLinkJson.ParseChain(body), genesis, KeyringStore.ChainHead,
            Convert.FromBase64String(broker.IdentityKey), settings.DeviceId);
        if (!result.Trusted)
            return result.Error;
        KeyringStore.ChainHead = result.Head;
        return null;
    }

    static string[] Strings(JsonElement array) => array.EnumerateArray().Select(e => e.GetString()!).ToArray();
}
