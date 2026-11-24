using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Win32;

namespace Tiresias.Agent;

/// <summary>
/// The user's folders, registry and environment variables as the agent reads and changes them:
/// this machine's, or, in demo mode (<see cref="DemoMode"/>), the made-up user's. Every store and
/// probe goes through here rather than to <see cref="Environment.GetFolderPath(Environment.SpecialFolder)"/>
/// or <see cref="Registry.CurrentUser"/> directly, so demo mode reaches all of them.
/// </summary>
public static class UserMachine
{
    /// <summary>A folder of the user's; system folders (Windows, Program Files) are always this machine's.</summary>
    public static string Folder(Environment.SpecialFolder folder)
    {
#if DEBUG
        if (DemoMode.Profile is { } profile)
            switch (folder)
            {
                case Environment.SpecialFolder.UserProfile:
                    return profile;
                case Environment.SpecialFolder.ApplicationData:
                    return Path.Combine(profile, "AppData", "Roaming");
                case Environment.SpecialFolder.LocalApplicationData:
                    return Path.Combine(profile, "AppData", "Local");
                case Environment.SpecialFolder.MyDocuments:
                    return Path.Combine(profile, "Documents");
                case Environment.SpecialFolder.Startup:
                    return Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup");
            }
#endif
        return Environment.GetFolderPath(folder);
    }

    /// <summary><c>%APPDATA%\Microsoft\UserSecrets</c>: where every project's user-secrets folder lives.</summary>
    public static string UserSecretsRoot =>
        DemoMode.On
            ? Path.Combine(Folder(Environment.SpecialFolder.ApplicationData), "Microsoft", "UserSecrets")
            // Two levels up from any id's file, as dotnet user-secrets resolves it (APPDATA first).
            : Path.GetDirectoryName(Path.GetDirectoryName(PathHelper.GetSecretsPathFromSecretsId("x")))!;

    /// <summary>The user's Windows account as <c>DOMAIN\user</c>, for a command that names it; the made-up user's in demo mode.</summary>
    public static string Account =>
        DemoMode.On ? $@"DEMO\{Path.GetFileName(Folder(Environment.SpecialFolder.UserProfile))}" : $@"{Environment.UserDomainName}\{Environment.UserName}";

    /// <summary><c>HKCU</c>. Not to be disposed.</summary>
    public static RegistryKey CurrentUser =>
#if DEBUG
        DemoMode.CurrentUser ??
#endif
        Registry.CurrentUser;

    /// <summary><c>HKLM</c>, read only; <c>null</c> in demo mode, whose machine has nothing there.</summary>
    public static RegistryKey? LocalMachine => DemoMode.On ? null : Registry.LocalMachine;

    const string EnvironmentKey = "Environment";

    /// <summary>A user environment variable (<c>HKCU\Environment</c>), expanded; <c>null</c> when unset.</summary>
    public static string? UserVariable(string name)
    {
        if (!DemoMode.On)
            return Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.User);
        using var key = CurrentUser.OpenSubKey(EnvironmentKey);
        return key?.GetValue(name) as string;
    }

    /// <summary>Sets a user environment variable, or removes it when <paramref name="value"/> is <c>null</c>, and tells running programs.</summary>
    public static void SetUserVariable(string name, string? value)
    {
        if (!DemoMode.On)
        {
            Environment.SetEnvironmentVariable(name, value, EnvironmentVariableTarget.User);
            return;
        }
        using var key = CurrentUser.CreateSubKey(EnvironmentKey, writable: true);
        if (value is null)
            key.DeleteValue(name, throwOnMissingValue: false);
        else
            key.SetValue(name, value);
    }
}
