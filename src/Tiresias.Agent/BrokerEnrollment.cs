using System.Security.Cryptography;
using System.Text.Json;
using NSec.Cryptography;
using Tiresias.Transport;

namespace Tiresias.Agent;

/// <summary>One tenant's broker identity, trust mode and vault are enrolled together.</summary>
public sealed record TenantConfig(string Name, Uri Url, string IdentityKey, string VaultPath, string? GenesisHash = null, bool Solo = false);

/// <summary>The broker's signed offer, kept across agent and CLI calls. Older caches contain only the lease ID or an unsigned recipient.</summary>
public sealed record OpenLease(string LeaseId, DateTimeOffset HardCapAt, string? LeaseKey = null, string? Signature = null)
{
    public LeaseOffer? Verify(string identityKey, DateTimeOffset now)
    {
        if (LeaseKey is null || Signature is null || HardCapAt <= now ||
            HardCapAt != DateTimeOffset.FromUnixTimeSeconds(HardCapAt.ToUnixTimeSeconds()) || string.IsNullOrEmpty(LeaseId))
            return null;
        try
        {
            var identity = PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(identityKey), KeyBlobFormat.RawPublicKey);
            var offer = new LeaseOffer(LeaseId, Convert.FromBase64String(LeaseKey), HardCapAt);
            return offer.LeaseKey.Length == 32 && offer.Verify(identity, Convert.FromBase64String(Signature)) ? offer : null;
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            return null;
        }
    }
}

/// <summary>The installing account's routing authority. Its service tenant is fixed at installation, and additional tenants are enrolled explicitly.</summary>
public sealed record BrokerEnrollment(string OwnerSid, TenantConfig Service)
{
    public string Write() => JsonSerializer.Serialize(this, JsonSerializerOptions.Web);

    public static BrokerEnrollment Read(string json) =>
        JsonSerializer.Deserialize<BrokerEnrollment>(json, JsonSerializerOptions.Web) is { OwnerSid.Length: > 0, Service: { Solo: true, GenesisHash.Length: > 0 } } binding
            ? binding
            : throw new InvalidDataException("The installed broker enrollment is incomplete.");

    public TenantConfig Require(TenantConfig selected, TenantConfig? enrolledRemote)
    {
        var expected = selected.Name == Service.Name ? Service : enrolledRemote;
        if (expected is null || selected != expected || selected.Url.AbsoluteUri != expected.Url.AbsoluteUri)
            throw new InvalidOperationException("The selected tenant does not match its installed enrollment. Restore the original settings or enroll the remote tenant from an administrator terminal.");
        return expected;
    }

    // A durable authorization precedes the registry change. Matching completion identifies a change that finished.
    internal static void Apply(string journal, string ownerSid, string operation, TenantConfig? target, Action change)
    {
        var id = Guid.NewGuid();
        var recipient = target is null ? null : Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(target, JsonSerializerOptions.Web)));
        using var stream = new FileStream(journal, FileMode.Append, FileAccess.Write, FileShare.Read);
        Record("authorized");
        change();
        Record("completed");

        void Record(string outcome)
        {
            stream.Write(JsonSerializer.SerializeToUtf8Bytes(new { id, time = DateTimeOffset.UtcNow, ownerSid, operation, recipient, outcome }, JsonSerializerOptions.Web));
            stream.WriteByte((byte)'\n');
            stream.Flush(flushToDisk: true);
        }
    }
}
