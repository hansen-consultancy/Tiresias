using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The facts guided setup phase 5 judges, read from this machine without admin rights or the
/// network: extension metadata, log-on entries and their signatures, the activity logs, the
/// blocklist. Names, paths and metadata only; no file is read beyond its header or signature.
/// </summary>
static partial class SurfaceProbe
{
    /// <summary>VS Code and its forks, by the folder in the user profile that holds their extensions.</summary>
    static readonly (string Folder, ExtensionHost Host)[] Hosts =
    [
        (".vscode", new("VS Code", "Code.exe", "code")),
        (".vscode-insiders", new("VS Code Insiders", "Code - Insiders.exe", "code-insiders")),
        (".cursor", new("Cursor", "Cursor.exe", "cursor")),
        (".windsurf", new("Windsurf", "Windsurf.exe", "windsurf")),
    ];

    public static IEnumerable<InstalledExtension> Extensions()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Hosts.SelectMany(h => Doctor.Extensions(h.Host, ReadOrNull(Path.Combine(profile, h.Folder, "extensions", "extensions.json"))));
    }

    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>The log-on entries that are on: those turned off in Task Manager or Settings are left out.</summary>
    public static IEnumerable<StartupEntry> StartupEntries()
    {
        var tray = TrayPrograms();
        List<StartupEntry> entries = [];
        foreach (var (hive, where) in new[] { (Registry.CurrentUser, StartupEntry.RunKey), (Registry.LocalMachine, StartupEntry.MachineRunKey) })
        {
            using var key = hive.OpenSubKey(RunKey);
            using var approved = hive.OpenSubKey(DisableStartup.ApprovedKey + "Run");
            if (key is null)
                continue;
            foreach (var name in key.GetValueNames())
                if (!Doctor.StartupTurnedOff(approved?.GetValue(name) as byte[])
                    && key.GetValue(name) is string command && Doctor.ExecutableIn(Environment.ExpandEnvironmentVariables(command)) is { } path)
                    entries.Add(Entry(name, where, path, name, tray));
        }
        var folder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        using var approvedFiles = Registry.CurrentUser.OpenSubKey(DisableStartup.ApprovedKey + "StartupFolder");
        if (Directory.Exists(folder))
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var item = Path.GetFileName(file);
                if (Doctor.StartupTurnedOff(approvedFiles?.GetValue(item) as byte[]))
                    continue;
                if (Path.GetExtension(file).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    entries.Add(Entry(Path.GetFileNameWithoutExtension(file), StartupEntry.StartupFolder, file, item, tray));
                else if (Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase) && ShortcutTarget(file) is { } target)
                    entries.Add(Entry(Path.GetFileNameWithoutExtension(file), StartupEntry.StartupFolder, target, item, tray));
            }
        return entries;
    }

    static StartupEntry Entry(string name, string where, string path, string item, HashSet<string> tray) =>
        new(name, where, path, File.Exists(path) ? IsSigned(path) : null, item, tray.Contains(path));

    /// <summary>Programs that have shown an icon in the notification area, from the taskbar's own record of them.</summary>
    static HashSet<string> TrayPrograms()
    {
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);
        using var icons = Registry.CurrentUser.OpenSubKey(@"Control Panel\NotifyIconSettings");
        if (icons is null)
            return paths;
        foreach (var name in icons.GetSubKeyNames())
        {
            using var icon = icons.OpenSubKey(name);
            if (icon?.GetValue("ExecutablePath") is string { Length: > 0 } path && ResolveKnownFolder(path) is { } resolved)
                paths.Add(resolved);
        }
        return paths;
    }

    /// <summary>A path that may start with a known folder's id, as the shell records them; <c>null</c> when the id isn't one this reads.</summary>
    static string? ResolveKnownFolder(string path)
    {
        if (!path.StartsWith('{') || path.IndexOf('}') is not (> 0 and var close))
            return path;
        return Guid.TryParse(path[..(close + 1)], out var id) && KnownFolder(id) is { } folder ? folder.TrimEnd('\\') + path[(close + 1)..] : null;
    }

    static string? KnownFolder(Guid id) => KnownFolders.TryGetValue(id, out var folder) && Environment.GetFolderPath(folder) is { Length: > 0 } path ? path : null;

    /// <summary>The known folders UserAssist names programs under.</summary>
    static readonly Dictionary<Guid, Environment.SpecialFolder> KnownFolders = new()
    {
        [new("6D809377-6AF0-444B-8957-A3773F02200E")] = Environment.SpecialFolder.ProgramFiles,
        [new("7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E")] = Environment.SpecialFolder.ProgramFilesX86,
        [new("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7")] = Environment.SpecialFolder.System,
        [new("D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27")] = Environment.SpecialFolder.SystemX86,
        [new("F38BF404-1D43-42F2-9305-67DE0B28FC23")] = Environment.SpecialFolder.Windows,
    };

    /// <summary>When the user last started each program from Explorer, the Start menu or the taskbar (UserAssist, per user, no admin).</summary>
    public static IEnumerable<ProgramRun> ProgramRuns()
    {
        const string executables = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
        using var key = Registry.CurrentUser.OpenSubKey(executables);
        if (key is null)
            return [];
        return Doctor.UserAssistRuns([.. key.GetValueNames().Select(n => (n, key.GetValue(n) as byte[]))], KnownFolder);
    }

    /// <summary>
    /// The global tools each package manager on <c>PATH</c> lists, given half a minute each; a manager
    /// that is missing, slow or fails lists none. Slow, so only <c>tir doctor --surface</c> asks.
    /// </summary>
    public static IEnumerable<GlobalTool> GlobalTools() =>
        Doctor.ToolManagers.SelectMany(m => Doctor.GlobalTools(m.Manager, Output(m.Manager, m.Arguments)));

    /// <summary>What a fixed command prints. <c>npm</c> is a batch file, so it goes through <c>cmd</c>; no argument comes from the machine.</summary>
    static string? Output(string program, string[] arguments)
    {
        var start = program == "npm" ? new ProcessStartInfo("cmd.exe") : new ProcessStartInfo(program);
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        foreach (var argument in program == "npm" ? ["/d", "/c", "npm", .. arguments] : arguments)
            start.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return null;
            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeSpan.FromSeconds(30)))
            {
                process.Kill(entireProcessTree: true);
                return null;
            }
            return output.Result;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    public static IEnumerable<CredentialUse> CredentialUses() =>
        Doctor.CredentialUses(Lines(AgentHost.ActivityPath).Concat(Lines(SoloBroker.AuditPath)));

    public static IEnumerable<string> BlockedPrograms() =>
        Doctor.BlockedPaths(ReadOrNull(Path.Combine(KeyringStore.Directory, "blocklist.json"))).Where(File.Exists);

    static string? ReadOrNull(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>A log's lines, shared with its writer; none when it is missing or locked.</summary>
    static string[] Lines(string path)
    {
        try
        {
            if (!File.Exists(path))
                return [];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>Where a shortcut points, through the shell's own link reader; <c>null</c> when it can't be read.</summary>
    static string? ShortcutTarget(string lnk)
    {
        try
        {
            if (Type.GetTypeFromProgID("WScript.Shell") is not { } type)
                return null;
            dynamic shell = Activator.CreateInstance(type)!;
            try
            {
                string target = shell.CreateShortcut(lnk).TargetPath;
                return string.IsNullOrEmpty(target) ? null : target;
            }
            finally
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
        catch (Exception e) when (e is COMException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the file carries a valid embedded Authenticode signature, checked offline (no revocation
    /// or URL retrieval). Windows' own files are signed by catalog, which this doesn't read, so they
    /// count as unchecked rather than unsigned; so do Store apps, signed as a package and started
    /// through an alias the check can't open.
    /// </summary>
    static unsafe bool? IsSigned(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (windows.Length > 0 && path.StartsWith(windows + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase))
            return null;
        fixed (char* file = path)
        {
            var info = new FileInfo { Size = (uint)sizeof(FileInfo), Path = file };
            var data = new TrustData
            {
                Size = (uint)sizeof(TrustData),
                UiChoice = 2, // WTD_UI_NONE
                RevocationChecks = 0, // WTD_REVOKE_NONE
                UnionChoice = 1, // WTD_CHOICE_FILE
                File = &info,
                StateAction = 1, // WTD_STATEACTION_VERIFY
                ProviderFlags = 0x10 | 0x1000, // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(-1, &action, &data);
            data.StateAction = 2; // WTD_STATEACTION_CLOSE
            _ = WinVerifyTrust(-1, &action, &data);
            return result == 0;
        }
    }

    static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    unsafe struct FileInfo
    {
        public uint Size;
        public char* Path;
        public nint Handle;
        public Guid* KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    unsafe struct TrustData
    {
        public uint Size;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public FileInfo* File;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static unsafe partial int WinVerifyTrust(nint window, Guid* action, TrustData* data);
}
