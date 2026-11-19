using System.Text.Json;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// Who each RavenDB service's certificate is and when it expires, recorded at setup so the doctor
/// can warn before it does without unsealing it. None of it is secret and changing it grants
/// nothing: a wrong date only shows or hides a warning. Kept beside the vault, not in it.
/// </summary>
public static class RavenCertificateStore
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 1;

    /// <summary>Per tenant, like the vault it mirrors: services in two tenants may share a slug.</summary>
    public static string FilePath => KeyringStore.TenantFile("raven-certificates");

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    sealed record Entry(string Subject, string Thumbprint, DateTimeOffset NotAfter);

    sealed record StoreFile(int V, Dictionary<string, Entry>? Certificates);

    /// <summary>Each RavenDB service in the vault with its certificate as recorded, or without dates when none is.</summary>
    public static IReadOnlyList<DoctorRavenCertificate> ForVault()
    {
        var recorded = Load();
        return [.. VaultEditor.Load().Services.Where(s => Vault.RavenSetupPlanner.Recognize(s) is not null)
            .Select(s => recorded.TryGetValue(s.Slug, out var e) ? new DoctorRavenCertificate(s.Slug, e.Subject, e.Thumbprint, e.NotAfter) : new(s.Slug, null, null, null))];
    }

    public static void Record(string service, RavenCertificateInfo certificate)
    {
        var all = Load();
        all[service] = new(certificate.Subject, certificate.Thumbprint, certificate.NotAfter);
        Directory.CreateDirectory(KeyringStore.Directory);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(new StoreFile(Version, all), Json));
        File.Move(temp, FilePath, overwrite: true);
    }

    /// <summary>The recorded certificates, or none when the file is missing, damaged or newer: a lost record costs a warning, never access.</summary>
    static Dictionary<string, Entry> Load()
    {
        try
        {
            return File.Exists(FilePath) && JsonSerializer.Deserialize<StoreFile>(File.ReadAllText(FilePath), Json) is { V: Version, Certificates: { } certificates }
                ? new(certificates, StringComparer.Ordinal)
                : new(StringComparer.Ordinal);
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            return new(StringComparer.Ordinal);
        }
    }
}
