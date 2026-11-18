using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace Tiresias.Agent;

/// <summary>Who is on the other end of a pipe: the client process's image path, from the pipe handle itself.</summary>
public static partial class PipeCaller
{
    /// <returns>The image path, <c>pid N</c> when the image can't be read, or <c>null</c> when Windows can't tell.</returns>
    public static string? Identify(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid))
            return null;
        try
        {
            using var process = Process.GetProcessById((int)pid);
            return process.MainModule?.FileName ?? $"pid {pid}";
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or ArgumentException)
        {
            return $"pid {pid}";
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);
}
