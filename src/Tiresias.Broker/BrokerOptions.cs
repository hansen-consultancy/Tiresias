using NSec.Cryptography;

namespace Tiresias.Broker;

/// <summary>The <c>Broker</c> configuration section. The listen address is the host's own <c>Urls</c> key.</summary>
public sealed class BrokerOptions
{
    public string VaultPath { get; set; } = "vault.json";
    public string AuditPath { get; set; } = "audit.jsonl";

    /// <summary>The broker's long-term Ed25519 identity, created on first start. The Keyring pins its public key.</summary>
    public string IdentityKeyPath { get; set; } = "identity.key";

    /// <summary>IANA or Windows zone the lease's daily cutoff is evaluated in.</summary>
    public string TimeZone { get; set; } = "Europe/Brussels";

    /// <summary>Device id → base64 raw Ed25519 public key. Only these may sign management requests.</summary>
    /// <remarks>Ignored when <see cref="TrustChainPath"/> is set.</remarks>
    public Dictionary<string, string> Devices { get; set; } = [];

    /// <summary>
    /// The tenant's trust chain. When set, the chain's active non-paper device keys are the only ones
    /// accepted, and the accepted head is kept beside it in <c>{path}.head</c>.
    /// </summary>
    public string? TrustChainPath { get; set; }

    /// <summary>Hex SHA-256 of the genesis link, pinned at setup. Required with <see cref="TrustChainPath"/>.</summary>
    public string? PinnedGenesisHash { get; set; }

    /// <summary>Most rows one <c>/sql</c> statement returns; the response says when it cut.</summary>
    public int SqlMaxRows { get; set; } = 1000;

    public int SqlTimeoutSeconds { get; set; } = 30;

    /// <summary>RFC 3161 TSA that anchors the audit log's head (e.g. <c>http://timestamp.digicert.com</c>). Unset, nothing is anchored.</summary>
    public string? TimestampAuthorityUrl { get; set; }
}

/// <summary>
/// The broker's long-term signing identity, at rest in an <see cref="IIdentityKeyStore"/>. It signs
/// lease offers and never protects a secret: losing it means re-pinning in the Keyring, not a vault
/// compromise, but whoever copies it can pose as this broker to a Keyring that pinned it.
/// </summary>
static class BrokerIdentity
{
    public static Key LoadOrCreate(IIdentityKeyStore store, ILogger logger)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        Key key;
        if (store.Load() is { } raw)
        {
            try
            {
                key = Key.Import(algorithm, raw, KeyBlobFormat.RawPrivateKey);
            }
            finally
            {
                Array.Clear(raw);
            }
        }
        else
        {
            key = Key.Create(algorithm, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var created = key.Export(KeyBlobFormat.RawPrivateKey);
            try
            {
                store.Save(created);
            }
            finally
            {
                Array.Clear(created);
            }
        }

        logger.LogInformation("Broker identity (pin this in the Keyring): {PublicKey}",
            Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
        return key;
    }
}
