using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Forwarder;

/// <summary>
/// The local process on the other end of a loopback TCP connection, from the TCP table
/// (<c>GetExtendedTcpTable</c>), and its image path when readable. Free of ASP.NET, so the admin
/// tier's service links it too.
/// </summary>
[SupportedOSPlatform("windows")]
static partial class TcpConnectionOwner
{
    const int TcpTableOwnerPidAll = 5;
    const int AfInet = 2;
    const int AfInet6 = 23;
    const uint ErrorInsufficientBuffer = 122;
    const uint ProcessQueryLimitedInformation = 0x1000;

    /// <summary>The process that opened a loopback connection to <paramref name="serverPort"/> from <paramref name="client"/>, and its image path when readable.</summary>
    public static (int Pid, string? Image)? Owner(IPEndPoint client, int serverPort) =>
        IPAddress.IsLoopback(client.Address) && OwningPid(client.AddressFamily == AddressFamily.InterNetworkV6, client.Port, serverPort) is { } pid
            ? (pid, ImagePath(pid))
            : null;
    /// <summary>The PID of the row whose local end is the client's port and remote end is ours.</summary>
    static unsafe int? OwningPid(bool ipv6, int clientPort, int serverPort)
    {
        // Row layouts: MIB_TCPROW_OWNER_PID (6 DWORDs) and MIB_TCP6ROW_OWNER_PID (56 bytes).
        var (family, rowSize, localPortAt, remotePortAt, pidAt) = ipv6 ? (AfInet6, 56, 20, 44, 52) : (AfInet, 24, 8, 16, 20);
        var size = 0;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(Math.Max(size, 4));
            try
            {
                var result = GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0);
                if (result == ErrorInsufficientBuffer)
                    continue;
                if (result != 0)
                    return null;

                var table = (byte*)buffer;
                var count = *(uint*)table;
                for (var i = 0; i < count; i++)
                {
                    var row = table + 4 + i * rowSize;
                    if (Port(*(uint*)(row + localPortAt)) == clientPort && Port(*(uint*)(row + remotePortAt)) == serverPort)
                        return (int)*(uint*)(row + pidAt);
                }
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return null;
    }

    /// <summary>Ports are stored in network byte order in the low 16 bits.</summary>
    static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    static unsafe string? ImagePath(int pid)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process.IsInvalid)
            return null;
        var chars = stackalloc char[1024];
        uint length = 1024;
        return QueryFullProcessImageName(process, 0, chars, ref length) ? new string(chars, 0, (int)length) : null;
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(nint table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sort, int family, int tableClass, uint reserved);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, char* name, ref uint size);
}
