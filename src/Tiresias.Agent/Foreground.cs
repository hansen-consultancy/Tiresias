using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Agent;

/// <summary>
/// Getting a prompt in front of the user. Windows lets a process take the foreground only when the
/// process the user is working in hands it the right (<c>AllowSetForegroundWindow</c>); the app
/// answers requests from <c>tir</c> and the NuGet plugin, which run in the background, so those
/// hand the right over before they ask (<see cref="AllowServerOf"/>). When Windows still refuses,
/// the window's taskbar button flashes instead.
/// </summary>
public static partial class Foreground
{
    /// <summary>
    /// Lets the process at the other end of a connected pipe take the foreground, for a prompt it
    /// shows while answering. Does nothing when this process may not hand the right on itself.
    /// </summary>
    public static void AllowServerOf(SafePipeHandle pipe)
    {
        if (GetNamedPipeServerProcessId(pipe, out var pid))
            AllowSetForegroundWindow(pid);
    }

    /// <summary>Brings the window to the front or, when Windows refuses, flashes its taskbar button until the user looks at it.</summary>
    /// <returns>Whether it is now the foreground window.</returns>
    public static bool Bring(nint window)
    {
        if (GetForegroundWindow() == window || (SetForegroundWindow(window) && GetForegroundWindow() == window))
            return true;
        Flash(window);
        return false;
    }

    /// <summary>Flashes until the window comes to the front.</summary>
    static void Flash(nint window)
    {
        const uint All = 0x3, UntilForeground = 0xC;
        var info = new FlashInfo { Size = (uint)Marshal.SizeOf<FlashInfo>(), Window = window, Flags = All | UntilForeground };
        FlashWindowEx(ref info);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FlashInfo
    {
        public uint Size;
        public nint Window;
        public uint Flags;
        public uint Count;
        public uint Timeout;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllowSetForegroundWindow(uint processId);

    [LibraryImport("user32.dll")]
    private static partial nint GetForegroundWindow();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetForegroundWindow(nint window);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FlashWindowEx(ref FlashInfo info);
}
