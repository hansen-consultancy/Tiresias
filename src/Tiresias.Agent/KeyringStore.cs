using System.Security.Cryptography;
using System.Text.Json;
using NSec.Cryptography;

namespace Tiresias.Agent;

/// <summary>The broker this Keyring talks to, pinned at enrolment. Every lease offer must verify against <see cref="IdentityKey"/>.</summary>
public sealed record BrokerPin(Uri Url, string IdentityKey);

/// <summary>Local settings. <see cref="RecoveryPublicKey"/> is only the public half; the private half exists on paper.</summary>
public sealed record KeyringSettings(string DeviceId, string VaultPath, string? RecoveryPublicKey);

/// <summary>
/// One broker this Keyring is enrolled with: a tenant (personal, customer), each with its own pinned
/// identity, vault and trust chain. <see cref="GenesisHash"/> is the trust chain's pinned genesis,
/// when the tenant runs one. <see cref="Solo"/>: the broker is this workstation's own, hosted by the
/// agent on loopback (see <see cref="SoloBroker"/>).
/// </summary>
public sealed record TenantConfig(string Name, Uri Url, string IdentityKey, string VaultPath, string? GenesisHash = null, bool Solo = false);

/// <summary>The lease <c>tir unlock</c> opened, so <c>tir agent</c>, <c>tir status</c> and <c>tir lock</c> can find it.</summary>
public sealed record OpenLease(string LeaseId, DateTimeOffset HardCapAt);

/// <summary>
/// Everything the Keyring keeps on disk, under <c>%LOCALAPPDATA%\Tiresias</c>. None of it is a
/// secret value: the device key is DPAPI-protected to the user's account, the rest is public or a pin.
/// Per-tenant state (pin, vault path, lease, trust-chain head) follows the tenant picked by
/// <see cref="Use"/>; a Keyring enrolled the old way, with <c>broker.json</c>, is one tenant named
/// <c>default</c>.
/// </summary>
public static class KeyringStore
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    static readonly byte[] DeviceKeyEntropy = "tiresias/v1/device-key"u8.ToArray();

    public static string Directory { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tiresias");

    public const string DefaultTenant = "default";

    static string? selected;

    static string BrokerPath => Path.Combine(Directory, "broker.json");
    static string TenantsPath => Path.Combine(Directory, "tenants.json");
    static string SettingsPath => Path.Combine(Directory, "keyring.json");
    static string LeasePath => Path.Combine(Directory, selected is null or DefaultTenant ? "lease.json" : $"lease-{selected}.json");
    static string ChainHeadPath => Path.Combine(Directory, selected is null or DefaultTenant ? "chain-head.json" : $"chain-head-{selected}.json");
    static string DeviceKeyPath => Path.Combine(Directory, "device.key");

    public static string DefaultVaultPath => Path.Combine(Directory, "vault.json");

    public static bool HasDeviceKey => File.Exists(DeviceKeyPath);

    /// <summary>Every tenant, from <c>tenants.json</c>, or the legacy single broker as <c>default</c>.</summary>
    public static IReadOnlyList<TenantConfig> Tenants =>
        Read<TenantConfig[]>(TenantsPath)
        ?? (Read<BrokerPin>(BrokerPath) is { } legacy ? [new(DefaultTenant, legacy.Url, legacy.IdentityKey, StoredSettings.VaultPath)] : []);

    /// <summary>Makes <paramref name="tenant"/> the one every per-tenant property refers to for the rest of the process.</summary>
    public static void Use(string tenant) => selected = tenant;

    public static TenantConfig? Tenant => Tenants.FirstOrDefault(t => t.Name == (selected ?? DefaultTenant)) ?? (selected is null && Tenants.Count == 1 ? Tenants[0] : null);

    public static BrokerPin? Broker => Tenant is { } t ? new(t.Url, t.IdentityKey) : null;

    /// <summary>Adds or replaces a tenant, moving a legacy <c>broker.json</c> into <c>tenants.json</c> on the way.</summary>
    public static void Enroll(TenantConfig tenant)
    {
        Write(TenantsPath, Tenants.Where(t => t.Name != tenant.Name).Append(tenant).ToArray());
        File.Delete(BrokerPath);
    }

    /// <summary>Device-wide settings, with the selected tenant's vault path.</summary>
    public static KeyringSettings Settings
    {
        get => Tenant is { } t ? StoredSettings with { VaultPath = t.VaultPath } : StoredSettings;
        set => Write(SettingsPath, value);
    }

    static KeyringSettings StoredSettings =>
        Read<KeyringSettings>(SettingsPath) ?? new(Environment.MachineName.ToLowerInvariant(), DefaultVaultPath, null);

    /// <summary>The trust-chain head this Keyring last accepted from the selected tenant's broker; a broker answering with an older one is rolling back.</summary>
    public static Trust.ChainHead? ChainHead
    {
        get => Read<Trust.ChainHead>(ChainHeadPath);
        set => Write(ChainHeadPath, value);
    }

    public static OpenLease? Lease
    {
        get => Read<OpenLease>(LeasePath);
        set => Write(LeasePath, value);
    }

    public static BrokerPin RequireBroker() =>
        Broker ?? throw new InvalidOperationException("Not enrolled. Run: tir enroll --broker <url> --broker-key <base64>");

    /// <summary>The device's public key as base64 raw Ed25519, for a broker's <c>Devices</c> list. Creates the key on first use.</summary>
    public static string DevicePublicKey()
    {
        using var key = LoadOrCreateDeviceKey();
        return Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>Throws when <paramref name="base64"/> isn't a raw Ed25519 public key.</summary>
    public static void ValidateBrokerKey(string base64) =>
        PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(base64), KeyBlobFormat.RawPublicKey);

    /// <summary>The device's Ed25519 signing key, created on first use and stored DPAPI-protected (CurrentUser).</summary>
    public static Key LoadOrCreateDeviceKey()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        if (File.Exists(DeviceKeyPath))
        {
            var raw = ProtectedData.Unprotect(File.ReadAllBytes(DeviceKeyPath), DeviceKeyEntropy, DataProtectionScope.CurrentUser);
            try
            {
                return Key.Import(algorithm, raw, KeyBlobFormat.RawPrivateKey);
            }
            finally
            {
                Array.Clear(raw);
            }
        }

        var key = Key.Create(algorithm, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var created = key.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            File.WriteAllBytes(DeviceKeyPath, ProtectedData.Protect(created, DeviceKeyEntropy, DataProtectionScope.CurrentUser));
        }
        finally
        {
            Array.Clear(created);
        }
        return key;
    }

    static T? Read<T>(string path) where T : class =>
        File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json) : null;

    static void Write<T>(string path, T? value) where T : class
    {
        if (value is null)
        {
            File.Delete(path);
            return;
        }
        System.IO.Directory.CreateDirectory(Directory);
        File.WriteAllText(path, JsonSerializer.Serialize(value, Json));
    }
}
