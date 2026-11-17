using Tiresias.Forwarder;
using Tiresias.Transport;

namespace Tiresias.Broker;

/// <summary>
/// Solo mode's stand-in for the forwarder: on a placeholder route, drops every client-sent
/// <c>X-Tiresias-*</c> header and records the local process on the loopback connection in
/// <see cref="ForwarderHeaders.ObservedProcess"/>. Recorded in the audit, never decided on.
/// </summary>
static class LoopbackCaller
{
    public static void Stamp(HttpContext context, IClientProcessLookup processes)
    {
        var headers = context.Request.Headers;
        foreach (var name in headers.Keys.Where(k => k.StartsWith("X-Tiresias-", StringComparison.OrdinalIgnoreCase)).ToArray())
            headers.Remove(name);
        if (processes.Describe(context.Connection) is { } observed)
            headers[ForwarderHeaders.ObservedProcess] = observed;
    }
}
