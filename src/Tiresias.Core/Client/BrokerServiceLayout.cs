using System.Text.Json;

namespace Tiresias.Client;

/// <summary>Whether solo mode's broker runs as the Windows service (docs/broker-service.md).</summary>
public enum BrokerServiceState
{
    NotInstalled,
    Stopped,
    Running,
}

/// <summary>What the service reads at start, written by an elevated install into its state folder.</summary>
public sealed record BrokerServiceConfig(string VaultPath, string GenesisHash, string TimeZone, string? OwnerSid = null, string? RevisionPublicKey = null)
{
    public const string FileName = "service.json";

    public byte[] Write() => JsonSerializer.SerializeToUtf8Bytes(this, JsonSerializerOptions.Web);

    /// <exception cref="InvalidDataException">Not a service config.</exception>
    public static BrokerServiceConfig Read(byte[] json)
    {
        var config = JsonSerializer.Deserialize<BrokerServiceConfig>(json, JsonSerializerOptions.Web);
        return config is { VaultPath.Length: > 0, GenesisHash.Length: > 0, TimeZone.Length: > 0 }
            ? config
            : throw new InvalidDataException($"{FileName} is incomplete.");
    }
}

/// <summary>
/// Where the solo broker's Windows service lives and how it is registered: binaries only admins
/// write, state only the service and admins write, its own virtual account (docs/broker-service.md).
/// </summary>
public static class BrokerServiceLayout
{
    public const string Name = "Tiresias";
    public const string Account = @"NT SERVICE\Tiresias";

    /// <summary>The broker identity's public key, base64, which the service writes at start for the install to pin.</summary>
    public const string IdentityPublicFile = "identity.pub";

    public static string BinaryFolder(string programFiles) => Path.Combine(programFiles, "Tiresias", "Broker");

    public static string StateFolder(string programData) => Path.Combine(programData, "Tiresias", "Broker");

    public static string AuditPath(string stateFolder, string ownerSid) => Path.Combine(stateFolder, $"audit-{ownerSid}.jsonl");

    /// <summary>
    /// The folders install makes owned by Administrators before granting the service, outermost first.
    /// Any user can create folders in <c>%ProgramData%</c>, and an owner can always change a folder's
    /// ACL back, so neither the state folder nor its parent may be one a user made.
    /// </summary>
    public static IReadOnlyList<string> SecuredFolders(string programData) => [Path.Combine(programData, "Tiresias"), StateFolder(programData)];

    /// <summary><c>sc.exe</c> arguments that register <paramref name="tirPath"/> as the service, under its virtual account.</summary>
    public static IReadOnlyList<string> CreateArguments(string tirPath) =>
        ["create", Name, "binPath=", $"\"{tirPath}\" solo service run", "obj=", Account, "start=", "auto", "DisplayName=", "Tiresias broker"];

    /// <summary><c>icacls.exe</c> arguments: the state folder for SYSTEM, Administrators and the service only.</summary>
    public static IReadOnlyList<string> StateFolderAcl(string stateFolder) =>
        [stateFolder, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", $"{Account}:(OI)(CI)M"];

    /// <summary>The broker's settings under the service, all paths inside <paramref name="stateFolder"/> but the vault.</summary>
    public static Dictionary<string, string?> BrokerSettings(string stateFolder, BrokerServiceConfig config) => new()
    {
        ["Broker:VaultPath"] = config.VaultPath,
        ["Broker:AuditPath"] = config.OwnerSid is { } sid ? AuditPath(stateFolder, sid) : Path.Combine(stateFolder, "audit.jsonl"),
        ["Broker:IdentityKeyPath"] = Path.Combine(stateFolder, "identity.key"),
        ["Broker:TrustChainPath"] = Path.Combine(stateFolder, "trust-chain.json"),
        ["Broker:PinnedGenesisHash"] = config.GenesisHash,
        ["Broker:TimeZone"] = config.TimeZone,
        ["Broker:IdentifyLoopbackCaller"] = "true",
        ["Broker:HighWaterPath"] = Path.Combine(stateFolder, "high-water.json"),
        ["Broker:RevisionPublicKey"] = config.RevisionPublicKey,
    };

    public static string TrustChainPath(string stateFolder) => Path.Combine(stateFolder, "trust-chain.json");
}
