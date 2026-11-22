using System.Security.Cryptography;
using NSec.Cryptography;
using Tiresias.EnvironmentVariables;
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
        var current = RecoveryEnrollment.Current();
        var legacy = current is null ? KeyringStore.Settings.RecoveryPublicKey : null;
        var offered = Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var changes = new List<(string Path, byte[] Digest, Action Write)>();
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
            var digest = Digest(path);
            var vault = VaultFile.Load(path);
            var changed = false;
            var secrets = vault.Secrets.Select(secret =>
            {
                var (outcome, result, opens) = RecoveryRewrap.Secret(secret, hello, recovery);
                Count(outcome, opens, $"vault: {secret.Slug}");
                changed |= outcome == RewrapOutcome.Rewrapped;
                return result;
            }).ToArray();
            if (changed)
                changes.Add((path, digest, () => VaultFile.Save(path, vault with { Secrets = secrets })));
        }

        foreach (var folder in Projects())
        {
            var kind = ProjectKind(folder);
            if (kind == SecretsFileKind.Invalid)
                Count(RewrapOutcome.DoesNotOpen, false, $"user secrets: {folder.Id}");
            if (kind != SecretsFileKind.Sealed)
                continue;
            var digest = Digest(folder.FilePath);
            var (outcome, text, opens) = UserSecretsVault.Rewrap(folder.Id, File.ReadAllText(folder.FilePath), hello, recovery);
            Count(outcome, opens, $"user secrets: {folder.Id}");
            if (outcome == RewrapOutcome.Rewrapped)
                changes.Add((folder.FilePath, digest, () => WriteText(folder.FilePath, text)));
        }

        if (EnvironmentStore.Exists)
        {
            var path = EnvironmentStore.FilePath;
            var digest = Digest(path);
            var (outcome, text, opens) = EnvironmentStore.Rewrap(hello, recovery);
            Count(outcome, opens, "environment variables");
            if (outcome == RewrapOutcome.Rewrapped)
                changes.Add((path, digest, () => WriteText(path, text)));
        }

        var solo = current is null && recoveryOpens == 0 ? RecoveryKey.VerifySoloPaper(recoveryKey) : SoloPaperProof.NoSolo;
        var (enroll, otherKeyKept) = PlanEnrollment(current, legacy, offered, items, recoveryOpens, solo);
        Apply(() =>
        {
            if (enroll)
                RecoveryEnrollment.Change(null, offered);
            else if (RecoveryEnrollment.Current() != current)
                throw RecoveryEnrollment.Changed();
        }, changes);
        return new(restored, alreadyOpen, notOpened, enroll, otherKeyKept);
    }

    internal static (bool Enroll, bool OtherKeyKept) PlanEnrollment(RecoveryBinding? current, string? legacy,
        string offered, int items, int recoveryOpens, SoloPaperProof solo)
    {
        // The offered recipient comes from the typed private key. A matching legacy hint still needs enrollment.
        var previous = current?.PublicKey ?? legacy;
        var matches = previous == offered;
        var serviceProof = current is null && solo == SoloPaperProof.MatchesServicePin;
        // A writable hint and a writable solo pin cannot vouch for a paper that opens nothing here.
        if (items > 0 && recoveryOpens == 0 && !(current is not null && matches) && !serviceProof)
            throw new InvalidOperationException("That recovery key opens none of the sealed secrets on this PC. Check the words you wrote down, or look for the paper from the PC that sealed them.");
        if (items == 0 && previous is not null && !matches && !serviceProof)
            throw new InvalidOperationException("That is not the recovery key this device stored. Check the words you wrote down.");

        var enroll = current is null && (serviceProof || matches || RecoveryRewrap.ShouldAdopt(legacy is not null, matches, items, recoveryOpens));
        if (enroll && recoveryOpens == 0 && solo == SoloPaperProof.Mismatch)
            throw new InvalidOperationException("That paper does not match the signing key of this PC's solo trust chain.");
        return (enroll, previous is not null && !matches && !enroll);
    }

    internal static void Apply(Action authorize, IReadOnlyList<(string Path, byte[] Digest, Action Write)> changes)
    {
        authorize();
        // A restore may wait for elevation while another process updates a sealed file.
        if (changes.Any(c => !Digest(c.Path).AsSpan().SequenceEqual(c.Digest)))
            throw new InvalidOperationException("A sealed file changed during recovery. Run the restore again.");
        foreach (var change in changes)
            change.Write();
    }

    static byte[] Digest(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }

    static void WriteText(string path, string text)
    {
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temp, text);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    /// <summary>
    /// Whether anything sealed is here: a vault secret or a sealed <c>secrets.json</c>. With no
    /// recovery key stored, that means the files came from another PC or an earlier setup. No prompt.
    /// </summary>
    public static bool AnythingSealed() => AnythingSealed(VaultPaths(), Projects(), EnvironmentStore.FilePath);

    internal static bool AnythingSealed(IEnumerable<string> vaults, IEnumerable<UserSecretsFolder> projects, string environmentPath) =>
        vaults.Any(path => VaultFile.Load(path).Secrets.Count > 0)
        || projects.Any(f => ProjectKind(f) is SecretsFileKind.Sealed or SecretsFileKind.Invalid)
        || new EnvironmentFile(environmentPath).Exists;

    /// <summary>The sealed items this Windows Hello key can't open, by name; empty when nothing needs restoring. No prompt beyond the unlocked wrapper.</summary>
    public static IReadOnlyList<string> Unopened(IKeyWrapper hello)
    {
        var names = new List<string>();
        foreach (var path in VaultPaths())
            foreach (var secret in VaultFile.Load(path).Secrets)
                if (!Opens(secret, hello))
                    names.Add($"vault: {secret.Slug}");
        foreach (var folder in Projects().Where(f => ProjectKind(f) == SecretsFileKind.Sealed))
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
            .Append(KeyringStore.DeviceVaultPath)
            .Append(KeyringStore.DefaultVaultPath)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(Exists);

    static IEnumerable<UserSecretsFolder> Projects()
    {
        var root = UserSecretsFiles.Root;
        return Exists(root) ? Directory.EnumerateDirectories(root).Select(d => new UserSecretsFolder(Path.GetFileName(d), d)) : [];
    }

    static SecretsFileKind ProjectKind(UserSecretsFolder folder) =>
        Exists(folder.FilePath) ? SecretsFile.Classify(File.ReadAllText(folder.FilePath)) : SecretsFileKind.None;

    // Recovery decisions must distinguish a missing path from one the desktop account cannot inspect.
    internal static bool Exists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
    }
}
