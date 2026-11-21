using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>The bits of Windows the app touches directly: capture exclusion, the taskbar theme, shell links, the Recycle Bin.</summary>
static partial class Desktop
{
    const uint WdaExcludeFromCapture = 0x11;

    /// <summary>
    /// Keeps a window out of screenshots, screen recordings and screen sharing (it shows as black),
    /// for windows that can show a secret value or the recovery key.
    /// </summary>
    public static void ExcludeFromCapture(Window window) =>
        window.SourceInitialized += (_, _) => SetWindowDisplayAffinity(new WindowInteropHelper(window).Handle, WdaExcludeFromCapture);

    /// <summary>Whether the taskbar is light, which picks the tray icon that stays visible on it.</summary>
    public static bool TaskbarIsLight()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("SystemUsesLightTheme") is int value && value != 0;
    }

    public static void Open(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            AppLog.Error(e, $"could not open {target}");
        }
    }

    /// <summary>Opens Explorer with the file selected. Windows paths can't hold a quote, so quoting it is enough.</summary>
    public static void Reveal(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false })?.Dispose();
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            AppLog.Error(e, $"could not show {path}");
        }
    }

    /// <summary>
    /// Runs the host's own <c>--uninstall-extension</c>. Its command is a batch file on <c>PATH</c>, so it
    /// goes through <c>cmd</c>; the id is checked to be a plain <c>publisher.name</c> first, because it
    /// comes from a file any program can write and <c>cmd</c> would act on metacharacters in it.
    /// </summary>
    /// <returns>Whether the command ran and reported success within a minute.</returns>
    public static async Task<bool> RemoveExtensionAsync(Tiresias.Client.RemoveExtension remove)
    {
        if (!Tiresias.Client.RemoveExtension.IsSafeId(remove.Id))
            return false;
        var start = new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in new[] { "/d", "/c", remove.Host.Cli, "--uninstall-extension", remove.Id })
            start.ArgumentList.Add(argument);
        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return false;
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(1));
            await process.WaitForExitAsync(timeout.Token);
            return process.ExitCode == 0;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or OperationCanceledException)
        {
            AppLog.Error(e, $"could not run {remove.Instruction}");
            return false;
        }
    }

    /// <summary>
    /// Saves one of the user's own uninstall entries to a <c>.reg</c> file beside the keyring, then
    /// deletes it. The key comes from the registry, so it is checked to be an Uninstall subkey first.
    /// </summary>
    /// <returns>The backup that puts it back; <c>null</c> when nothing was deleted.</returns>
    public static async Task<string?> RemoveEntryAsync(Tiresias.Client.RemoveEntry remove)
    {
        const string prefix = @"HKCU";
        if (remove.Machine || !Tiresias.Client.RemoveEntry.IsSafeKey(remove.Key))
            return null;
        var folder = Path.Combine(KeyringStore.Directory, "removed-entries");
        var backup = Path.Combine(folder, $"{DateTime.Now:yyyyMMdd-HHmmss} {remove.BackupName}");
        var start = new ProcessStartInfo("reg.exe") { UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in new[] { "export", remove.Key, backup, "/y" })
            start.ArgumentList.Add(argument);
        try
        {
            Directory.CreateDirectory(folder);
            using (var process = Process.Start(start))
            {
                if (process is null)
                    return null;
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                await process.WaitForExitAsync(timeout.Token);
                if (process.ExitCode != 0 || !File.Exists(backup))
                    return null;
            }
            Registry.CurrentUser.DeleteSubKeyTree(remove.Key[prefix.Length..], throwOnMissingSubKey: false);
            return backup;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or OperationCanceledException
                                      or IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            AppLog.Error(e, $"could not remove the uninstall entry for {remove.Name}");
            return null;
        }
    }

    public static void OpenHelloSettings() => Open("ms-settings:signinoptions");

    public static void OpenDataFolder() => Open(KeyringStore.Directory);

    /// <summary>Sorts an exception into the problem the user is told about. The full exception goes to the log.</summary>
    public static ProblemKind Classify(Exception e) => e switch
    {
        HelloException { Problem: HelloProblem.NotSetUp } => ProblemKind.HelloNotSetUp,
        HelloException { Problem: HelloProblem.Cancelled } => ProblemKind.HelloCancelled,
        HelloException { Problem: HelloProblem.Expired } => ProblemKind.HelloExpired,
        HelloException { Problem: HelloProblem.CredentialMissing } => ProblemKind.HelloCredentialMissing,
        HelloException => ProblemKind.HelloUnavailable,
        HttpRequestException or TaskCanceledException => ProblemKind.BrokerUnreachable,
        JsonException or InvalidDataException or FormatException or CryptographicException => ProblemKind.VaultUnreadable,
        UnauthorizedAccessException or IOException => ProblemKind.FileAccess,
        _ => ProblemKind.Unexpected,
    };

    /// <summary>Moves a folder or a file to the Recycle Bin, quietly: the caller has asked already.</summary>
    /// <returns>Whether it went; one open in another program stays where it is.</returns>
    public static unsafe bool Recycle(string directory)
    {
        const uint Delete = 3;
        const ushort AllowUndo = 0x40, NoConfirmation = 0x10, Silent = 0x4, NoErrorUi = 0x400;
        // The shell takes a list of paths ended by an empty one.
        var from = directory + "\0\0";
        fixed (char* path = from)
        {
            var op = new ShellFileOperation { Function = Delete, From = path, Flags = AllowUndo | NoConfirmation | Silent | NoErrorUi };
            return SHFileOperation(&op) == 0 && op.AnyAborted == 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    unsafe struct ShellFileOperation
    {
        public nint Window;
        public uint Function;
        public char* From;
        public char* To;
        public ushort Flags;
        public int AnyAborted;
        public nint NameMappings;
        public char* ProgressTitle;
    }

    [LibraryImport("shell32.dll", EntryPoint = "SHFileOperationW")]
    private static unsafe partial int SHFileOperation(ShellFileOperation* operation);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowDisplayAffinity(nint hwnd, uint affinity);
}
