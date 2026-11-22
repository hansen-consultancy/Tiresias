using System.Runtime.InteropServices;
using Microsoft.Win32;
using Tiresias.EnvironmentVariables;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>A variable in the user's Windows environment, described without its value.</summary>
public sealed record UserVariable(string Name, int Length, bool LooksSecret);

/// <summary>
/// The sealed environment: user environment variables moved out of <c>HKCU\Environment</c> into
/// <c>%LOCALAPPDATA%\Tiresias\environment.json</c>, sealed as a user-secrets file is (for Windows
/// Hello and the recovery key), and handed only to a process the user allowed. Moving in is checked
/// before anything is deleted, and <see cref="PutBack"/> undoes it.
/// </summary>
public static partial class EnvironmentStore
{
    const string RegistryKey = "Environment";

    public static string FilePath => Path.Combine(KeyringStore.Directory, "environment.json");

    public static bool Exists => new EnvironmentFile(FilePath).Exists;

    /// <summary>The sealed environment and the version it was read from; empty and 0 when nothing is sealed yet.</summary>
    public static (SealedEnvironment Environment, int Version) Open(IKeyWrapper hello) => new EnvironmentFile(FilePath).Open(hello);

    public static EnvironmentSnapshot ReadForDelivery(IKeyWrapper hello) => new EnvironmentFile(FilePath).ReadForDelivery(hello);

    /// <summary>Seals <paramref name="environment"/> as the version after <paramref name="loadedVersion"/>.</summary>
    /// <exception cref="InvalidOperationException">No recovery key: nothing sealed may depend on the TPM alone.</exception>
    public static void Save(SealedEnvironment environment, int loadedVersion, IKeyWrapper hello)
    {
        var recovery = RecoveryKey.Wrapper()
            ?? throw new InvalidOperationException("No recovery key yet, so nothing can be sealed. Create it first (first-run wizard, or tir recovery init).");
        Directory.CreateDirectory(KeyringStore.Directory);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, UserSecretsVault.Seal(EnvironmentFile.Id, loadedVersion + 1, environment.ToDocument(), [hello, recovery]));
        File.Move(temp, FilePath, overwrite: true);
    }

    /// <summary>The sealed environment given back to <paramref name="hello"/> by <paramref name="recovery"/>; see <see cref="RecoveryRestore"/>.</summary>
    public static (RewrapOutcome Outcome, string FileText, bool RecoveryOpens) Rewrap(IKeyWrapper hello, IKeyWrapper recovery) =>
        new EnvironmentFile(FilePath).Rewrap(hello, recovery);

    /// <summary>Whether <paramref name="hello"/> opens the authenticated environment.</summary>
    public static bool Opens(IKeyWrapper hello) => new EnvironmentFile(FilePath).Opens(hello);

    /// <summary>The user's own variables (not the machine's), by name, each with its length and whether it looks like a secret.</summary>
    public static IReadOnlyList<UserVariable> UserVariables()
    {
        using var key = UserMachine.CurrentUser.OpenSubKey(RegistryKey);
        if (key is null)
            return [];
        return [.. key.GetValueNames()
            .Where(name => name.Length > 0)
            .Select(name => (Name: name, Value: Raw(key, name)))
            .Where(v => v.Value is not null)
            .Select(v => new UserVariable(v.Name, v.Value!.Length, SealedVariables.LooksSecret(v.Name, v.Value.Length, SealedVariables.IsPath(v.Value))))
            .OrderBy(v => v.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// Moves <paramref name="names"/> from the user's environment into the sealed one: sealed, opened
    /// again and compared, and only then deleted from the registry. Programs started afterwards no
    /// longer inherit them; those already running keep their copy.
    /// </summary>
    /// <returns>The names moved; a name that isn't a user variable is passed over.</returns>
    public static IReadOnlyList<string> Protect(IEnumerable<string> names, IKeyWrapper hello)
    {
        using var key = UserMachine.CurrentUser.OpenSubKey(RegistryKey, writable: true)
            ?? throw new InvalidOperationException("This Windows account has no user environment.");
        var moving = names.Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(name => (Name: name, Value: Raw(key, name)))
            .Where(v => !string.IsNullOrEmpty(v.Value))
            .Select(v => new SealedVariable(v.Name, v.Value!, key.GetValueKind(v.Name) == RegistryValueKind.ExpandString))
            .ToArray();
        if (moving.Length == 0)
            return [];

        var (sealedNow, version) = Open(hello);
        Save(sealedNow.WithGlobal(moving), version, hello);
        var check = Open(hello).Environment.Global.ToDictionary(v => v.Name, StringComparer.OrdinalIgnoreCase);
        if (moving.Any(v => !check.TryGetValue(v.Name, out var back) || back != v))
            throw new InvalidOperationException("The sealed copy didn't read back the same, so nothing was removed from Windows.");

        foreach (var variable in moving)
            key.DeleteValue(variable.Name, throwOnMissingValue: false);
        AnnounceChange();
        return [.. moving.Select(v => v.Name)];
    }

    /// <summary>
    /// Seals <paramref name="variable"/> globally or for <paramref name="folder"/>, replacing any of
    /// the same name there. A global one, once the sealed copy reads back the same, also deletes a
    /// copy left in the user's Windows environment: otherwise the old value would stay readable, and
    /// a later Protect would seal it over the new one. A folder one leaves Windows alone, since it
    /// replaces nothing outside that folder.
    /// </summary>
    /// <returns>Whether a copy was removed from Windows.</returns>
    public static bool Set(SealedVariable variable, string? folder, IKeyWrapper hello)
    {
        var (sealedNow, version) = Open(hello);
        Save(folder is null ? sealedNow.WithGlobal([variable]) : sealedNow.WithFolder(folder, [variable]), version, hello);
        if (folder is not null)
            return false;
        if (Open(hello).Environment.Global.FirstOrDefault(v => string.Equals(v.Name, variable.Name, StringComparison.OrdinalIgnoreCase)) != variable)
            throw new InvalidOperationException("The sealed copy didn't read back the same.");
        using var key = UserMachine.CurrentUser.OpenSubKey(RegistryKey, writable: true);
        if (key is null || Raw(key, variable.Name) is null)
            return false;
        key.DeleteValue(variable.Name, throwOnMissingValue: false);
        AnnounceChange();
        return true;
    }

    /// <summary>Writes <paramref name="names"/> back to the user's environment as they were, then drops them from the sealed one.</summary>
    /// <returns>The names put back. Only the global set came from Windows; a folder set's variable is never put back.</returns>
    public static IReadOnlyList<string> PutBack(IEnumerable<string> names, IKeyWrapper hello)
    {
        var (sealedNow, version) = Open(hello);
        var wanted = names.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var returning = sealedNow.Global.Where(v => wanted.Contains(v.Name)).ToArray();
        if (returning.Length == 0)
            return [];
        using (var key = UserMachine.CurrentUser.CreateSubKey(RegistryKey, writable: true))
            foreach (var variable in returning)
                key.SetValue(variable.Name, variable.Value, variable.Expandable ? RegistryValueKind.ExpandString : RegistryValueKind.String);
        AnnounceChange();
        Save(sealedNow.WithoutGlobal(returning.Select(v => v.Name)), version, hello);
        return [.. returning.Select(v => v.Name)];
    }

    /// <summary>A value as stored: <c>%VAR%</c> references unexpanded, so writing it back changes nothing.</summary>
    static string? Raw(RegistryKey key, string name) =>
        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;

    /// <summary>Tells Explorer, and through it every program it starts later, that the environment changed (as <c>setx</c> does).</summary>
    static void AnnounceChange()
    {
        if (!DemoMode.On)
            SendMessageTimeoutW(HwndBroadcast, WmSettingChange, 0, RegistryKey, SmtoAbortIfHung, 5000, out _);
    }

    static readonly nint HwndBroadcast = 0xffff;
    const uint WmSettingChange = 0x001A;
    const uint SmtoAbortIfHung = 0x0002;

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint SendMessageTimeoutW(nint window, uint message, nuint wParam, string lParam, uint flags, uint timeoutMs, out nuint result);
}
