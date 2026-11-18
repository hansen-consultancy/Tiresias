using System.Runtime.InteropServices;
using Microsoft.Win32;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// Keeps the folder holding <c>tir.exe</c> on the user's <c>PATH</c> (HKCU, no admin rights): added at
/// every start, so a moved install heals itself, and removed on uninstall. Only new terminals see a
/// change; one already open keeps its old <c>PATH</c>.
/// </summary>
static partial class TirOnPath
{
    const string Key = "Environment";
    const string Name = "Path";

    /// <summary>Adds the folder when it is missing. Never throws: a failure is logged, and <c>tir</c> still works by full path.</summary>
    public static void Ensure() => Change(UserPath.With, "added");

    /// <summary>Velopack's uninstall hook: takes the folder back off.</summary>
    public static void Remove() => Change(UserPath.Without, "removed");

    static void Change(Func<string?, string, string?> edit, string verb)
    {
        try
        {
            if (UserPath.TirFolder(AppContext.BaseDirectory, File.Exists) is not { } folder)
                return;
            using var env = Registry.CurrentUser.CreateSubKey(Key, writable: true);
            // Unexpanded, so entries like %USERPROFILE%\bin stay as the user wrote them.
            var current = env.GetValue(Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            if (edit(current, folder) is not { } changed)
                return;
            var kind = current is not null && env.GetValueKind(Name) == RegistryValueKind.String ? RegistryValueKind.String : RegistryValueKind.ExpandString;
            env.SetValue(Name, changed, kind);
            SendMessageTimeoutW(HwndBroadcast, WmSettingChange, 0, Key, SmtoAbortIfHung, 1000, out _);
            AppLog.Info($"{verb} {folder} on the user PATH");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            AppLog.Error(e, "user PATH");
        }
    }

    const nint HwndBroadcast = 0xffff;
    const uint WmSettingChange = 0x001A;
    const uint SmtoAbortIfHung = 0x0002;

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint SendMessageTimeoutW(nint hwnd, uint msg, nint wParam, string lParam, uint flags, uint timeout, out nint result);
}
