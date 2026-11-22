using NSec.Cryptography;
using Tiresias.Client;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>What <see cref="RecoveryRestore.Run"/> did.</summary>
/// <param name="Restored">Items the recovery key gave back to this Windows Hello key.</param>
/// <param name="AlreadyOpen">Items this Windows Hello key opened already.</param>
/// <param name="NotOpened">Items neither key opens, by name ("vault: llm", "user secrets: &lt;id&gt;").</param>
/// <param name="KeyAdopted">This device now stores the typed key as its recovery key.</param>
/// <param name="OtherKeyKept">This device keeps a different recovery key, which some of its secrets need.</param>
public sealed record RestoreSummary(int Restored, int AlreadyOpen, IReadOnlyList<string> NotOpened, bool KeyAdopted, bool OtherKeyKept);

/// <summary>
/// Restoring from the paper recovery key: every sealed item on this device (each vault's secrets and
/// every sealed <c>secrets.json</c>, and the sealed environment) that this Windows Hello key can't open is given back to it, as
/// <see cref="RecoveryRewrap"/> describes. For a new PC, a reset Windows Hello, or files copied from
/// another machine. Everything is worked out before anything is written.
/// </summary>
public static class RecoveryRestore
{
    /// <exception cref="InvalidOperationException">The key opens none of the sealed items here, or (with nothing sealed) isn't the one this device stored.</exception>
    public static RestoreSummary Run(ReadOnlySpan<byte> recoveryKey, IKeyWrapper hello)
    {
        using var key = Key.Import(KeyAgreementAlgorithm.X25519, recoveryKey, KeyBlobFormat.RawPrivateKey);
        var recovery = X25519KeyWrapper.ForKey(RecoveryKey.WrapperId, key);
        var settings = KeyringStore.Settings;
        var stored = settings.RecoveryPublicKey is { } s ? Convert.FromBase64String(s) : null;
        var storedMatches = stored is not null && PaperKey.Matches(recoveryKey, stored);

        var vaults = new List<(string Path, VaultDocument Vault, bool Changed)>();
        var files = new List<(string Path, string Text)>();
        int restored = 0, alreadyOpen = 0, recoveryOpens = 0, items = 0;
        var notOpened = new List<string>();

        void Count(RewrapOutcome outcome, bool opens, string name)
        {
            items++;
            if (opens)
                recoveryOpens++;
            switch (outcome)
            {
                case RewrapOutcome.Rewrapped: restored++; break;
                case RewrapOutcome.AlreadyOpens: alreadyOpen++; break;
                default: notOpened.Add(name); break;
            }
        }

        foreach (var path in VaultPaths())
        {
            var vault = VaultFile.Load(path);
            var changed = false;
            var secrets = vault.Secrets.Select(secret =>
            {
                var (outcome, result, opens) = RecoveryRewrap.Secret(secret, hello, recovery);
                Count(outcome, opens, $"vault: {secret.Slug}");
                changed |= outcome == RewrapOutcome.Rewrapped;
                return result;
            }).ToArray();
            vaults.Add((path, vault with { Secrets = secrets }, changed));
        }

        foreach (var folder in UserSecretsFiles.All().Where(f => f.Kind == SecretsFileKind.Sealed))
        {
            var (outcome, text, opens) = UserSecretsVault.Rewrap(folder.Id, File.ReadAllText(folder.FilePath), hello, recovery);
            Count(outcome, opens, $"user secrets: {folder.Id}");
            if (outcome == RewrapOutcome.Rewrapped)
                files.Add((folder.FilePath, text));
        }

        if (EnvironmentStore.Exists)
        {
            var (outcome, text, opens) = EnvironmentStore.Rewrap(hello, recovery);
            Count(outcome, opens, "environment variables");
            if (outcome == RewrapOutcome.Rewrapped)
                files.Add((EnvironmentStore.FilePath, text));
        }

        if (!storedMatches && (items > 0 ? recoveryOpens == 0 : stored is not null))
            throw new InvalidOperationException(items > 0
                ? "That recovery key opens none of the sealed secrets on this PC. Check the words you wrote down, or look for the paper from the PC that sealed them."
                : "That is not the recovery key this device stored. Check the words you wrote down.");

        foreach (var (path, vault, changed) in vaults.Where(v => v.Changed))
            VaultFile.Save(path, vault);
        foreach (var (path, text) in files)
        {
            var temp = path + ".tmp";
            File.WriteAllText(temp, text);
            File.Move(temp, path, overwrite: true);
        }

        var adopt = RecoveryRewrap.ShouldAdopt(stored is not null, storedMatches, items, recoveryOpens);
        if (adopt)
            KeyringStore.Settings = KeyringStore.Settings with { RecoveryPublicKey = Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)) };
        return new(restored, alreadyOpen, notOpened, adopt, stored is not null && !storedMatches && !adopt);
    }

    /// <summary>
    /// Whether anything sealed is here: a vault secret or a sealed <c>secrets.json</c>. With no
    /// recovery key stored, that means the files came from another PC or an earlier setup. No prompt.
    /// </summary>
    public static bool AnythingSealed() =>
        VaultPaths().Any(path => VaultFile.Load(path).Secrets.Count > 0)
        || UserSecretsFiles.All().Any(f => f.Kind == SecretsFileKind.Sealed)
        || EnvironmentStore.Exists;

    /// <summary>The sealed items this Windows Hello key can't open, by name; empty when nothing needs restoring. No prompt beyond the unlocked wrapper.</summary>
    public static IReadOnlyList<string> Unopened(IKeyWrapper hello)
    {
        var names = new List<string>();
        foreach (var path in VaultPaths())
            foreach (var secret in VaultFile.Load(path).Secrets)
                if (!Opens(secret, hello))
                    names.Add($"vault: {secret.Slug}");
        foreach (var folder in UserSecretsFiles.All().Where(f => f.Kind == SecretsFileKind.Sealed))
            if (!UserSecretsVault.Opens(folder.Id, File.ReadAllText(folder.FilePath), hello))
                names.Add($"user secrets: {folder.Id}");
        if (EnvironmentStore.Exists && !EnvironmentStore.Opens(hello))
            names.Add("environment variables");
        return names;
    }

    static bool Opens(SealedSecret secret, IKeyWrapper hello)
    {
        var dek = SecretEnvelope.UnwrapDek(secret, hello);
        if (dek is null)
            return false;
        Array.Clear(dek);
        return true;
    }

    /// <summary>Every tenant's vault and the device's own, once each, where the file exists.</summary>
    static IEnumerable<string> VaultPaths() =>
        KeyringStore.Tenants.Select(t => t.VaultPath)
            .Append(KeyringStore.Settings.VaultPath)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(File.Exists);
}
