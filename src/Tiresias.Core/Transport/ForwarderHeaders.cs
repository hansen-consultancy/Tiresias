namespace Tiresias.Transport;

/// <summary>Headers the forwarder adds to a request it passes on. The broker strips every <c>X-Tiresias-*</c> header before the upstream.</summary>
public static class ForwarderHeaders
{
    /// <summary>
    /// Image path and PID of the local process on the loopback connection, as the forwarder saw it,
    /// e.g. <c>C:\tools\export.exe (pid 4242)</c>. Reported by the forwarder, not signed: the broker
    /// records it, it does not decide on it.
    /// </summary>
    public const string ObservedProcess = "X-Tiresias-Observed-Process";

    /// <summary>
    /// The origin the local client used (<c>http://127.0.0.1:7781</c>), so a rewritten RavenDB topology
    /// points the client back at the forwarder rather than at the broker. The broker honours only a
    /// loopback origin: anything else could steer a client's later requests to another host.
    /// </summary>
    public const string PublicBase = "X-Tiresias-Public-Base";
}
