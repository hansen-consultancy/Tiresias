using System.Globalization;
using System.Runtime.InteropServices;
using Tiresias.Agent;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

internal static partial class Program
{
    static int Main(string[] args)
    {
        if (!SetDefaultDllDirectories((uint)DllImportSearchPath.System32))
            return 1;

        try
        {
            switch (args)
            {
                case ["recovery", "enroll-recipient", var sid, var revision, var key]:
                    RecoveryEnrollmentAuthority.ApplyElevated(sid, revision, key);
                    return 0;
                case ["recovery", "enroll-recipient", var sid, var revision, var key, "unused", var nonce, var pid]
                    when Guid.TryParseExact(nonce, "D", out _) &&
                         int.TryParse(pid, NumberStyles.None, CultureInfo.InvariantCulture, out var desktopPid) && desktopPid > 0:
                    RecoveryEnrollmentAuthority.ApplyElevated(sid, revision, key, onlyIfUnused: true,
                        confirmUnused: () => { RecoveryChangeGuard.Confirm(nonce, desktopPid); return true; });
                    return 0;
                default:
                    return 2;
            }
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException
            or System.Security.SecurityException or System.ComponentModel.Win32Exception or ArgumentException or TimeoutException or OperationCanceledException)
        {
            return 1;
        }
    }

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint flags);
}
