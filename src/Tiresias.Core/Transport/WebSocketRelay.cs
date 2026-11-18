using System.Net.WebSockets;
using System.Runtime.CompilerServices;

namespace Tiresias.Transport;

/// <summary>
/// Joins two WebSockets: every message goes across whole (text or binary, split where the sender
/// split it), and a close on either side closes the other with the same status. The forwarder joins
/// the local client to the broker; the broker joins that to the node.
/// </summary>
public static class WebSocketRelay
{
    /// <summary>Bytes each way when the relay ended.</summary>
    public readonly record struct Moved(long Up, long Down);

    /// <param name="client">The side that asked for the connection; <see cref="Moved.Up"/> counts what it sent.</param>
    /// <param name="ct">Cancelling aborts both sockets (a lease that ended, a server shutting down).</param>
    public static async Task<Moved> RunAsync(WebSocket client, WebSocket server, CancellationToken ct)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var upBytes = new StrongBox<long>();
        var downBytes = new StrongBox<long>();
        var up = PumpAsync(client, server, upBytes, stop.Token);
        var down = PumpAsync(server, client, downBytes, stop.Token);
        var first = await Task.WhenAny(up, down);
        // One direction is done. After a close it was passed on: give the other side a moment to
        // finish the handshake. After a failure there is nothing to wait for.
        if (first.IsCompletedSuccessfully)
            stop.CancelAfter(TimeSpan.FromSeconds(5));
        else
            await stop.CancelAsync();
        try
        {
            await Task.WhenAll(up, down);
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException or IOException)
        {
            client.Abort();
            server.Abort();
        }
        return new(upBytes.Value, downBytes.Value);
    }

    static async Task PumpAsync(WebSocket from, WebSocket to, StrongBox<long> total, CancellationToken ct)
    {
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var received = await from.ReceiveAsync(buffer, ct);
            if (received.MessageType == WebSocketMessageType.Close)
            {
                if (to.State is WebSocketState.Open or WebSocketState.CloseReceived)
                    await to.CloseOutputAsync(from.CloseStatus ?? WebSocketCloseStatus.NormalClosure, from.CloseStatusDescription, ct);
                return;
            }
            total.Value += received.Count;
            await to.SendAsync(buffer.AsMemory(0, received.Count), received.MessageType, received.EndOfMessage, ct);
        }
    }
}
