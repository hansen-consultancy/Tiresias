using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Tiresias.Policy;

namespace Tiresias.Vault;

/// <summary>The vault in memory: sealed secrets and the services whose grants use them.</summary>
public sealed record VaultDocument(IReadOnlyList<SealedSecret> Secrets, IReadOnlyList<Service> Services)
{
    public SealedSecret? FindSecret(string slug) => Secrets.FirstOrDefault(s => s.Slug == slug);

    public Service? FindService(string slug) => Services.FirstOrDefault(s => s.Slug == slug);
}

/// <summary>
/// The vault on disk: one JSON file holding ciphertext and policy, never a plaintext value or a
/// usable key. Writes are atomic (temp file in the same directory, then a rename over the old one),
/// so a crash mid-write leaves the previous vault intact.
/// </summary>
public static class VaultFile
{
    /// <summary>Policy regexes run on attacker-chosen paths, so each match is time-boxed.</summary>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static VaultDocument Load(string path)
    {
        using var stream = File.OpenRead(path);
        var dto = JsonSerializer.Deserialize<VaultDto>(stream, Json)
            ?? throw new InvalidDataException($"Vault file '{path}' is empty.");
        if (dto.Version is not (1 or 2))
            throw new InvalidDataException($"Vault file '{path}' has unsupported version {dto.Version}.");

        return new(
            dto.Secrets.Select(s => new SealedSecret(s.Slug, s.Version, s.WrappedDeks, s.Nonce, s.Ciphertext, s.BoundToPolicy)).ToArray(),
            dto.Services.Select(ToService).ToArray());
    }

    public static void Save(string path, VaultDocument vault)
    {
        // Version 2 only once a secret is bound, so a vault without one stays readable by older builds.
        var dto = new VaultDto(
            vault.Secrets.Any(s => s.BoundToPolicy) ? 2 : 1,
            vault.Secrets.Select(s => new SecretDto(s.Slug, s.Version, new Dictionary<string, byte[]>(s.WrappedDeks), s.Nonce, s.Ciphertext, s.BoundToPolicy)).ToArray(),
            vault.Services.Select(ToDto).ToArray());

        var full = Path.GetFullPath(path);
        var temp = Path.Combine(Path.GetDirectoryName(full)!, $".{Path.GetFileName(full)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write))
            {
                JsonSerializer.Serialize(stream, dto, Json);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, full, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    public static Regex Compile(string pattern) => new(pattern, RegexOptions.CultureInvariant, RegexTimeout);

    static Service ToService(ServiceDto s) => new(
        s.Slug,
        s.Upstream,
        s.Grants.Select(g => new Grant(
            g.Name,
            g.SecretSlug,
            new RequestRule(
                g.Methods.Select(m => m.ToUpperInvariant()).ToHashSet(),
                g.Allow.Select(Compile).ToArray(),
                g.Deny.Select(Compile).ToArray(),
                g.MaxBodyBytes),
            g.RequiresElevation,
            g.IssuesLogins)).ToArray());

    static ServiceDto ToDto(Service s) => new(
        s.Slug,
        s.Upstream,
        s.Grants.Select(g => new GrantDto(
            g.Name,
            g.SecretSlug,
            g.RequiresElevation,
            g.Rule.Methods.Order().ToArray(),
            g.Rule.Allow.Select(r => r.ToString()).ToArray(),
            (g.Rule.Deny ?? []).Select(r => r.ToString()).ToArray(),
            g.Rule.MaxBodyBytes,
            g.IssuesLogins)).ToArray());

    sealed record VaultDto(int Version, SecretDto[] Secrets, ServiceDto[] Services);

    /// <param name="BoundToPolicy">Version 2 only; absent reads as <c>false</c>.</param>
    sealed record SecretDto(string Slug, int Version, Dictionary<string, byte[]> WrappedDeks, byte[] Nonce, byte[] Ciphertext,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool BoundToPolicy = false);

    sealed record ServiceDto(string Slug, Uri Upstream, GrantDto[] Grants);

    /// <param name="IssuesLogins">Absent in vaults written before it existed, which reads as <c>false</c>.</param>
    sealed record GrantDto(string Name, string SecretSlug, bool RequiresElevation, string[] Methods, string[] Allow, string[] Deny, long? MaxBodyBytes, bool IssuesLogins = false);
}
