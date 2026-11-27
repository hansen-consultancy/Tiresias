using System.Runtime.InteropServices;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// Puts <c>tir</c> where an update can't trip over it (<see cref="StableTir"/>, #177): copies this
/// version's folder out of Velopack's install folder, points the shim in <c>bin</c> at it, keeps
/// <c>bin</c> on the user's <c>PATH</c> (HKCU, no admin rights) in place of the install folder, and
/// removes the copies no <c>tir</c> runs from any more. Done at every start of an installed app, so a
/// moved install or an older one that put its own folder on PATH heals itself. Only new terminals
/// see a PATH change; one already open keeps its old <c>PATH</c>.
/// </summary>
static partial class TirInstall
{
    const string Key = "Environment";
    const string Name = "Path";

    static StableTir Layout => new(KeyringStore.Directory);

    /// <summary>Never throws: a failure is logged, and the <c>tir</c> already on PATH keeps working.</summary>
    public static void Ensure(string version)
    {
        if (UserPath.TirFolder(AppContext.BaseDirectory, File.Exists) is not { } installed)
            return;
        var layout = Layout;
        try
        {
            Copy(installed, layout, version);
            if (!PlaceShim(installed, layout))
            {
                // A package without the shim: tir stays on PATH from the install folder, as before #177.
                Change(path => UserPath.With(path, installed), $"put {installed} on the user PATH");
                return;
            }
            WritePointer(layout, layout.Tir(version));
            Change(path => UserPath.Replace(path, installed, layout.Bin), $"put {layout.Bin} on the user PATH");
            Prune(layout, version);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            AppLog.Error(e, "installing tir");
        }
    }

    /// <summary>Velopack's uninstall hook: takes <c>bin</c> (and an older install's own folder) back off PATH and removes the copies.</summary>
    public static void Remove()
    {
        var layout = Layout;
        try
        {
            if (UserPath.TirFolder(AppContext.BaseDirectory, File.Exists) is { } installed)
                Change(path => UserPath.Without(path, installed), $"took {installed} off the user PATH");
            Change(path => UserPath.Without(path, layout.Bin), $"took {layout.Bin} off the user PATH");
            // A tir still running keeps its files; what can go, goes.
            DeleteQuietly(layout.Bin);
            DeleteQuietly(layout.Versions);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            AppLog.Error(e, "removing tir");
        }
    }

    /// <summary>Copies into a staging folder and renames it last, so a version folder is always whole.</summary>
    static void Copy(string from, StableTir layout, string version)
    {
        var to = layout.Version(version);
        if (Directory.Exists(to))
            return;
        var staging = to + ".partial";
        if (Directory.Exists(staging))
            Directory.Delete(staging, recursive: true);
        var source = Path.TrimEndingDirectorySeparator(from);
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(staging, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }
        Directory.Move(staging, to);
        AppLog.Info($"copied tir {version} to {to}");
    }

    /// <summary>
    /// A running shim can't be overwritten but can be renamed, so a changed one moves the old aside
    /// (removed once nothing runs it) and takes its name.
    /// </summary>
    static bool PlaceShim(string installed, StableTir layout)
    {
        var shim = Path.Combine(installed, TirShim.PackagedName);
        if (!File.Exists(shim))
            return false;
        Directory.CreateDirectory(layout.Bin);
        foreach (var old in Directory.EnumerateFiles(layout.Bin, "*.old"))
            TryDelete(old);
        if (File.Exists(layout.Shim) && File.ReadAllBytes(layout.Shim).AsSpan().SequenceEqual(File.ReadAllBytes(shim)))
            return true;
        if (File.Exists(layout.Shim))
            File.Move(layout.Shim, $"{layout.Shim}.{Guid.NewGuid():N}.old");
        File.Copy(shim, layout.Shim);
        AppLog.Info($"placed the tir shim at {layout.Shim}");
        return true;
    }

    static void WritePointer(StableTir layout, string tir)
    {
        if (File.Exists(layout.Pointer) && File.ReadAllText(layout.Pointer).Trim() == tir)
            return;
        var staging = layout.Pointer + ".new";
        File.WriteAllText(staging, tir);
        File.Move(staging, layout.Pointer, overwrite: true);
        AppLog.Info($"tir on PATH now runs {tir}");
    }

    /// <summary>
    /// Windows lets a folder be moved or partly deleted while a program runs from it, so a copy is
    /// removed only when no program runs from it or works in it; one in use waits for the next start.
    /// </summary>
    static void Prune(StableTir layout, string version)
    {
        var names = Directory.EnumerateDirectories(layout.Versions).Select(Path.GetFileName).OfType<string>().ToList();
        foreach (var name in StableTir.Stale(names, version))
        {
            var folder = Path.Combine(layout.Versions, name);
            if (InstallFolderUsers.Find(folder).Count > 0 || AnyFileLoaded(folder))
                continue;
            try
            {
                Directory.Delete(folder, recursive: true);
                AppLog.Info($"removed the tir copy {name}");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                AppLog.Info($"left the tir copy {name}: {e.Message}");
            }
        }
    }

    /// <summary>
    /// Whether a program has a file of <paramref name="folder"/> loaded: an exe or DLL a process
    /// runs can't be opened for writing. This sees a <c>tir</c> run elevated or as another account
    /// too, which <see cref="InstallFolderUsers"/> can't read.
    /// </summary>
    static bool AnyFileLoaded(string folder)
    {
        foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
        {
            if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                using var _ = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return true;
            }
        }
        return false;
    }

    static void DeleteQuietly(string folder)
    {
        if (!Directory.Exists(folder))
            return;
        foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
            TryDelete(file);
        try
        {
            Directory.Delete(folder, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }

    static void TryDelete(string file)
    {
        try
        {
            File.Delete(file);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }

    static void Change(Func<string?, string?> edit, string done)
    {
        using var env = Registry.CurrentUser.CreateSubKey(Key, writable: true);
        // Unexpanded, so entries like %USERPROFILE%\bin stay as the user wrote them.
        var current = env.GetValue(Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        if (edit(current) is not { } changed)
            return;
        var kind = current is not null && env.GetValueKind(Name) == RegistryValueKind.String ? RegistryValueKind.String : RegistryValueKind.ExpandString;
        env.SetValue(Name, changed, kind);
        SendMessageTimeoutW(HwndBroadcast, WmSettingChange, 0, Key, SmtoAbortIfHung, 1000, out _);
        AppLog.Info(done);
    }

    const nint HwndBroadcast = 0xffff;
    const uint WmSettingChange = 0x001A;
    const uint SmtoAbortIfHung = 0x0002;

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint SendMessageTimeoutW(nint hwnd, uint msg, nint wParam, string lParam, uint flags, uint timeout, out nint result);
}
