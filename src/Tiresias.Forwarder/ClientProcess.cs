using System.Net;
using System.Runtime.Versioning;

namespace Tiresias.Forwarder;

/// <summary>
/// Who is on the other end of a loopback connection: the local process that opened it, as
/// <c>{image path} (pid {pid})</c>. This is what the forwarder saw, not what the client claims.
/// </summary>
interface IClientProcessLookup
{
    /// <returns><c>null</c> when the connection isn't local or the owner can't be found.</returns>
    string? Describe(ConnectionInfo connection);
}

sealed class NoClientProcessLookup : IClientProcessLookup
{
    public string? Describe(ConnectionInfo connection) => null;
}

/// <summary>
/// Maps the client's loopback port to its owning PID through the TCP table
/// (<c>GetExtendedTcpTable</c>), then to an image path. Under a separate service account the image
/// path of the user's processes may be unreadable; the PID is still reported.
/// </summary>
[SupportedOSPlatform("windows")]
sealed class WindowsClientProcessLookup : IClientProcessLookup
{
    public string? Describe(ConnectionInfo connection)
    {
        if (connection.RemoteIpAddress is not { } remote || !IPAddress.IsLoopback(remote))
            return null;
        return TcpConnectionOwner.Owner(new IPEndPoint(remote, connection.RemotePort), connection.LocalPort) is { } owner
            ? $"{owner.Image ?? "unknown image"} (pid {owner.Pid})"
            : null;
    }

    /// <summary>The process that opened a loopback connection to <paramref name="serverPort"/> from <paramref name="client"/>, and its image path when readable.</summary>
    public static (int Pid, string? Image)? Owner(IPEndPoint client, int serverPort) => TcpConnectionOwner.Owner(client, serverPort);
}
