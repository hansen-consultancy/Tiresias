using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Agent;

// The elevated helper links just this half. It accepts a veto and cannot ask the desktop to perform any action.
internal sealed partial class RecoveryChangeGuard
{
    static string PipeName(string nonce) =>
        Guid.TryParseExact(nonce, "D", out var id) && id != Guid.Empty && nonce == id.ToString("D")
            ? "tiresias.recovery." + nonce : throw new InvalidOperationException("Invalid recovery check.");

    internal static void Confirm(string nonce, int expectedDesktopPid) =>
        ConfirmAsync(nonce, expectedDesktopPid, TimeSpan.FromMinutes(1)).GetAwaiter().GetResult();

    internal static async Task ConfirmAsync(string nonce, int expectedDesktopPid, TimeSpan timeout)
    {
        var name = PipeName(nonce);
        if (expectedDesktopPid <= 0)
            throw new InvalidOperationException("Invalid recovery check.");
        using var self = Process.GetCurrentProcess();
        const int queryLimitedAndSynchronize = 0x1000 | 0x100000;
        // Retain the process object. A process created after the helper cannot be the one that launched it.
        using var desktop = OpenProcess(queryLimitedAndSynchronize, false, expectedDesktopPid);
        if (desktop.IsInvalid || !GetProcessTimes(desktop, out var started, out _, out _, out _) ||
            started > self.StartTime.ToFileTimeUtc() || WaitForSingleObject(desktop, 0) != WaitTimeout)
            throw new UnauthorizedAccessException("The initiating desktop process is no longer available.");

        using var deadline = new CancellationTokenSource(timeout);
        using var pipe = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
        await pipe.ConnectAsync(deadline.Token).ConfigureAwait(false);
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid) || pid != expectedDesktopPid ||
            !GetNamedPipeServerSessionId(pipe.SafePipeHandle, out var session) || session != self.SessionId)
            throw new UnauthorizedAccessException("The initiating desktop process could not be verified.");
        var answer = new byte[1];
        if (await pipe.ReadAsync(answer, deadline.Token).ConfigureAwait(false) != 1 || answer[0] != 1 ||
            WaitForSingleObject(desktop, 0) != WaitTimeout)
            throw new InvalidOperationException("The desktop did not confirm that the recovery key is still unused.");
    }

    const uint WaitTimeout = 258;

    [LibraryImport("kernel32.dll")]
    private static partial SafeProcessHandle OpenProcess(int access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [LibraryImport("kernel32.dll")]
    private static partial uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerSessionId(SafePipeHandle pipe, out uint session);
}
