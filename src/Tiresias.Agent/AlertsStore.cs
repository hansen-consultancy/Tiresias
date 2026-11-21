using Tiresias.Alerts;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// <c>%LOCALAPPDATA%\Tiresias\alerts.json</c>: the sinks and their credentials, sealed for Windows
/// Hello and the recovery key (docs/alerts.md, <i>Sinks</i>). The format and its rules are
/// <see cref="AlertsFile"/>'s; this only reads and writes the file.
/// </summary>
public static class AlertsStore
{
    public static string FilePath => Path.Combine(KeyringStore.Directory, "alerts.json");

    /// <summary>Whether a sealed alerts file exists here, for the recovery restore. No prompt.</summary>
    public static bool IsSealed => File.Exists(FilePath) && Protocol.SecretsFile.Classify(File.ReadAllText(FilePath)) == Protocol.SecretsFileKind.Sealed;

    /// <inheritdoc cref="AlertsFile.Open"/>
    public static (AlertsConfig? Config, int Version) Open(IKeyWrapper hello) =>
        AlertsFile.Open(File.Exists(FilePath) ? File.ReadAllText(FilePath) : null, hello);

    /// <summary>Seals <paramref name="config"/> as the version after <paramref name="loadedVersion"/>.</summary>
    /// <exception cref="InvalidOperationException">No recovery key: nothing sealed may depend on the TPM alone.</exception>
    public static void Save(AlertsConfig config, int loadedVersion, IKeyWrapper hello)
    {
        var recovery = RecoveryKey.Wrapper()
            ?? throw new InvalidOperationException("No recovery key yet, so nothing can be sealed. Create it first (first-run wizard, or tir recovery init).");
        Directory.CreateDirectory(KeyringStore.Directory);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, AlertsFile.Seal(config, loadedVersion, hello, recovery));
        File.Move(temp, FilePath, overwrite: true);
    }

    /// <summary>The alerts file given back to <paramref name="hello"/> by <paramref name="recovery"/>; see <see cref="RecoveryRestore"/>.</summary>
    public static (RewrapOutcome Outcome, string FileText, bool RecoveryOpens) Rewrap(IKeyWrapper hello, IKeyWrapper recovery) =>
        UserSecretsVault.Rewrap(AlertsFile.Id, File.ReadAllText(FilePath), hello, recovery);

    /// <summary>Whether <paramref name="hello"/> opens the alerts file; decrypts nothing else.</summary>
    public static bool Opens(IKeyWrapper hello) => UserSecretsVault.Opens(AlertsFile.Id, File.ReadAllText(FilePath), hello);
}
