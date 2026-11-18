using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// Changes to the selected tenant's vault file, for <c>tir</c> and the app alike. Secrets are
/// sealed to Windows Hello and the recovery key before they touch the disk. In solo mode the running
/// broker notices the file changed and uses it from its next request.
/// </summary>
public static class VaultEditor
{
    public static string Path => KeyringStore.Settings.VaultPath;

    /// <summary>The vault, or an empty one when the file doesn't exist yet.</summary>
    public static VaultDocument Load() => File.Exists(Path) ? VaultFile.Load(Path) : new VaultDocument([], []);

    /// <summary>Seals <paramref name="value"/> as the next version of <paramref name="slug"/>, replacing the previous one.</summary>
    /// <param name="hello">The agent's open wrapper; <c>null</c> opens one here, which may show the Hello prompt.</param>
    /// <returns>The version written.</returns>
    /// <exception cref="InvalidOperationException">No recovery key yet, or an empty value.</exception>
    public static int SealSecret(string slug, ReadOnlySpan<byte> value, HelloKeyWrapper? hello = null)
    {
        if (value.IsEmpty)
            throw new InvalidOperationException("Empty value.");
        var recovery = RecoveryKey.Wrapper()
            ?? throw new InvalidOperationException("No recovery key yet. Run tir recovery init first, so no secret depends on the TPM alone.");
        var vault = Load();
        var version = (vault.FindSecret(slug)?.Version ?? 0) + 1;
        SealedSecret secret;
        if (hello is not null)
            secret = SecretEnvelope.Seal(slug, version, value, [hello, recovery]);
        else
        {
            using var opened = HelloKeyWrapper.Open(create: true);
            secret = SecretEnvelope.Seal(slug, version, value, [opened, recovery]);
        }
        VaultFile.Save(Path, vault with { Secrets = [.. vault.Secrets.Where(s => s.Slug != slug), secret] });
        return version;
    }

    /// <summary>Adds a service planned by <see cref="ServicePlanner"/>; its secret must be in the vault already.</summary>
    /// <exception cref="InvalidOperationException">A service with that slug exists, or its secret is missing.</exception>
    public static void AddService(Service service)
    {
        var vault = Load();
        if (vault.FindService(service.Slug) is not null)
            throw new InvalidOperationException($"A service named {service.Slug} exists already.");
        if (service.Grants.FirstOrDefault(g => vault.FindSecret(g.SecretSlug) is null) is { } orphan)
            throw new InvalidOperationException($"Secret {orphan.SecretSlug} isn't in the vault; add it first.");
        VaultFile.Save(Path, vault with { Services = [.. vault.Services, service] });
    }

    /// <summary>Adds the service, or replaces the one with its slug: setting a SQL Server up again.</summary>
    /// <exception cref="InvalidOperationException">Its secret is missing.</exception>
    public static void SetService(Service service)
    {
        var vault = Load();
        if (service.Grants.FirstOrDefault(g => vault.FindSecret(g.SecretSlug) is null) is { } orphan)
            throw new InvalidOperationException($"Secret {orphan.SecretSlug} isn't in the vault; add it first.");
        VaultFile.Save(Path, vault with { Services = [.. vault.Services.Where(s => s.Slug != service.Slug), service] });
    }

    /// <summary>Removes a service and keeps its secrets, which other services may share.</summary>
    /// <returns>Whether there was such a service.</returns>
    public static bool RemoveService(string slug)
    {
        var vault = Load();
        if (vault.FindService(slug) is null)
            return false;
        VaultFile.Save(Path, vault with { Services = [.. vault.Services.Where(s => s.Slug != slug)] });
        return true;
    }
}
