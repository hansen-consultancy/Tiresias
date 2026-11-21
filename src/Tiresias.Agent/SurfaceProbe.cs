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

    public static IEnumerable<StartupEntry> StartupEntries()
    {
        List<StartupEntry> entries = [];
        foreach (var (hive, where) in new[] { (Registry.CurrentUser, "Run key"), (Registry.LocalMachine, "machine Run key") })
        {
            using var key = hive.OpenSubKey(RunKey);
            if (key is null)
                continue;
            foreach (var name in key.GetValueNames())
                if (key.GetValue(name) is string command && Doctor.ExecutableIn(Environment.ExpandEnvironmentVariables(command)) is { } path)
                    entries.Add(Entry(name, where, path));
        }
        var folder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (Directory.Exists(folder))
            foreach (var file in Directory.EnumerateFiles(folder))
                if (Path.GetExtension(file).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    entries.Add(Entry(Path.GetFileNameWithoutExtension(file), "Startup folder", file));
                else if (Path.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase) && ShortcutTarget(file) is { } target)
                    entries.Add(Entry(Path.GetFileNameWithoutExtension(file), "Startup folder", target));
        return entries;
    }

    static StartupEntry Entry(string name, string where, string path) =>
        File.Exists(path) ? new(name, where, path, IsSigned(path)) : new(name, where, path, null);

    public static IEnumerable<DecoyUseRecord> DecoyUses() => Doctor.DecoyUses(Lines(AgentHost.ActivityPath));

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
