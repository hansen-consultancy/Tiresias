using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Tiresias.Windows;

/// <summary>The signed-in account of a Windows session, independent of alternate administrator credentials.</summary>
[SupportedOSPlatform("windows")]
internal sealed partial record WindowsSessionAccount(string Name, string Sid)
{
    internal static WindowsSessionAccount? Find(int session, bool requireDomain = false)
    {
        var name = SessionString(session, 5 /* WTSUserName */);
        var domain = SessionString(session, 7 /* WTSDomainName */);
        if (string.IsNullOrEmpty(name) || (requireDomain && string.IsNullOrEmpty(domain)))
            return null;
        try
        {
            var account = new NTAccount(domain ?? "", name);
            return new(account.Value, account.Translate(typeof(SecurityIdentifier)).Value);
        }
        catch (SystemException)
        {
            // Domain lookup can fail even when the session still has a user. Its identity must be established.
            return null;
        }
    }

    static string? SessionString(int session, int infoClass)
    {
        if (!WTSQuerySessionInformationW(0, session, infoClass, out var buffer, out _))
            return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQuerySessionInformationW(nint server, int session, int infoClass, out nint buffer, out int bytes);
    [LibraryImport("wtsapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial void WTSFreeMemory(nint buffer);
}
