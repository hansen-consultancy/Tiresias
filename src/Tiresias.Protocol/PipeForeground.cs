using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Protocol;

/// <summary>
/// The client half of getting a prompt in front of the user. Windows lets a process take the
/// foreground only when the process the user is working in hands it the right; <c>tir</c> and an
/// app loading its user secrets ask the Tiresias app over a pipe, and the app may answer with a
/// consent dialog or a Hello prompt, so they hand the right to whoever serves the pipe before they ask.
/// </summary>
public static partial class PipeForeground
{
    /// <summary>
    /// Lets the process serving a connected pipe take the foreground. Does nothing off Windows, or
    /// when this process may not hand the right on itself.
    /// </summary>
    public static void AllowServer(NamedPipeClientStream pipe)
    {
        if (ServerProcessId(pipe) is { } pid)
            AllowSetForegroundWindow(pid);
    }

    internal static uint? ServerProcessId(NamedPipeClientStream pipe) =>
        OperatingSystem.IsWindows() && GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid) ? pid : null;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllowSetForegroundWindow(uint processId);
}
