using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// Reads the signals <see cref="DeveloperTools"/> decides from: whether a folder, file, registry key
/// or pipe exists. No process starts, no admin rights, nothing is opened. Machine-wide places
/// (Program Files, <c>HKLM</c>, <c>PATH</c>, pipes) are this PC's, so a demo reads them as absent and
/// shows what its made-up profile holds.
/// </summary>
static class DeveloperSignals
{
    public static DeveloperView View() => DeveloperTools.Plan(Read(), AppSettings.Load().DeveloperTools);

    /// <summary>The signals that showed the tools, as words: "the .NET SDK is installed, git is set up".</summary>
    public static string Reasons(DeveloperView view) => string.Join(", ", view.Because.Select(s => Text.Get(DeveloperTools.Key(s))));

    public static Dictionary<DeveloperSignal, bool?> Read()
    {
        var profile = UserMachine.Folder(Environment.SpecialFolder.UserProfile);
        var roaming = UserMachine.Folder(Environment.SpecialFolder.ApplicationData);
        var machine = !DemoMode.On;
        return new()
        {
            [DeveloperSignal.DotNetSdk] = !machine ? false : Check(DotNetSdk),
            [DeveloperSignal.UserSecrets] = Check(() => HasEntries(UserMachine.UserSecretsRoot)),
            [DeveloperSignal.Git] = Check(() => File.Exists(Path.Combine(profile, ".gitconfig")) || machine && OnPath("git.exe")),
            [DeveloperSignal.VisualStudio] = !machine ? false : Check(() => File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft Visual Studio", "Installer", "vswhere.exe"))),
            [DeveloperSignal.Rider] = Check(() => Directory.Exists(Path.Combine(roaming, "JetBrains"))
                && Directory.EnumerateDirectories(Path.Combine(roaming, "JetBrains"), "Rider*").Any()),
            [DeveloperSignal.VsCode] = Check(() => new[] { ".vscode", ".vscode-insiders", ".cursor", ".windsurf" }
                .Any(f => Directory.Exists(Path.Combine(profile, f, "extensions")))),
            [DeveloperSignal.Wsl] = Check(() =>
            {
                using var lxss = UserMachine.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss");
                return lxss?.SubKeyCount > 0;
            }),
            [DeveloperSignal.Docker] = !machine ? false : Check(() => Directory.GetFiles(@"\\.\pipe\")
                .Any(p => Path.GetFileName(p).StartsWith("docker", StringComparison.OrdinalIgnoreCase))),
            [DeveloperSignal.SealedVariables] = Check(() => EnvironmentStore.Exists),
            [DeveloperSignal.VaultServices] = Check(() => VaultEditor.Load().Services.Count > 0),
            [DeveloperSignal.ProjectFolders] = Check(() => ProjectIndexStore.Load().Folders.Count > 0),
        };
    }

    /// <summary>An SDK, not only the runtime ordinary apps install.</summary>
    static bool DotNetSdk()
    {
        using var key = UserMachine.LocalMachine?.OpenSubKey(@"SOFTWARE\dotnet\Setup\InstalledVersions\x64\sdk");
        return key?.ValueCount > 0
            || HasEntries(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "sdk"));
    }

    static bool HasEntries(string folder) => Directory.Exists(folder) && Directory.EnumerateFileSystemEntries(folder).Any();

    static bool OnPath(string file) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Any(d => File.Exists(Path.Combine(d.Trim('"'), file)));

    static bool? Check(Func<bool> read)
    {
        try
        {
            return read();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException
            or System.Security.SecurityException or System.Text.Json.JsonException or InvalidDataException)
        {
            AppLog.Error(e, "reading a developer signal");
            return null;
        }
    }
}
