using Tiresias.Client;
using Tiresias.Agent;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary>Picks the tenant a command line is about, per <see cref="TenantRouter"/>, and selects it in <see cref="KeyringStore"/>.</summary>
static class TenantSelection
{
    public static void Apply(CommandLine line)
    {
        var command = line.At(0);
        if (command is null or "enroll" or "recovery" or "solo" or "secrets")
            return;
        var tenants = KeyringStore.Tenants;
        if (tenants.Count == 0)
            return; // Not enrolled: each command already says so.

        var known = tenants.Select(t => new TenantServices(t.Name, ServicesIn(t.VaultPath))).ToArray();
        string?[] services = command is "grant" or "elevate" or "exec" && line.At(1) is { } list
            ? [.. list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)]
            : [null];
        var choices = services.Select(s => TenantRouter.Resolve(known, s, line.Option("--tenant"))).ToArray();
        if (choices.FirstOrDefault(c => c.Tenant is null) is { } failed)
            throw new UsageException(failed.Error!);
        if (choices.Select(c => c.Tenant).Distinct().Count() > 1)
            throw new UsageException("Those services belong to different tenants; run one tir exec per tenant.");
        KeyringStore.Use(choices[0].Tenant!);
    }

    static HashSet<string> ServicesIn(string vaultPath) =>
        File.Exists(vaultPath) ? VaultFile.Load(vaultPath).Services.Select(s => s.Slug).ToHashSet() : [];
}
