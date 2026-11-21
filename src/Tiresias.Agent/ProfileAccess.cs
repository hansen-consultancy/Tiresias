using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Agent;

/// <summary>Uses the signed-in user's ordinary desktop token for profile work performed during elevated setup.</summary>
public static partial class ProfileAccess
{
    public static void Run(Action action) => Run(() =>
    {
        action();
        return true;
    });

    public static T Run<T>(Func<T> action)
    {
        using var current = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator))
            return action();

        // Taking the token from this session's shell also rejects elevation under another user's credentials.
        GetWindowThreadProcessId(GetShellWindow(), out var pid);
        if (pid == 0)
            throw new InvalidOperationException("Run setup from the enrolled user's signed-in Windows desktop.");
        using var shell = Process.GetProcessById(checked((int)pid));
        if (!OpenProcessToken(shell.SafeHandle, TokenQuery | TokenDuplicate, out var token))
            throw new InvalidOperationException("The signed-in user's desktop token could not be opened.");
        using (token)
        using (var desktop = new WindowsIdentity(token.DangerousGetHandle()))
        {
            if (desktop.User is null || desktop.User != current.User ||
                !GetTokenInformation(token, TokenElevation, out var elevated, sizeof(uint), out _) || elevated != 0)
                throw new InvalidOperationException("Elevate from the enrolled user's ordinary Windows desktop with the same Windows account.");
            return WindowsIdentity.RunImpersonated(token, action);
        }
    }

    const uint TokenQuery = 0x0008, TokenDuplicate = 0x0002;
    const int TokenElevation = 20;

    [LibraryImport("user32.dll")]
    private static partial nint GetShellWindow();

    [LibraryImport("user32.dll")]
    private static partial uint GetWindowThreadProcessId(nint window, out uint pid);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, out uint info, int length, out int returned);
}
