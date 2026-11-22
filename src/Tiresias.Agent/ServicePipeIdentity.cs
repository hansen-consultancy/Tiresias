using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Agent;

[SupportedOSPlatform("windows")]
internal static partial class ServicePipeIdentity
{
    internal static bool Matches(NamedPipeClientStream pipe, int serviceProcessId) =>
        serviceProcessId > 0 && GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var server) && server == serviceProcessId;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
}
