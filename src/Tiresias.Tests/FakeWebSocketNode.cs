using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;

namespace Tiresias.Tests;

/// <summary>The far end of a relayed WebSocket for a fake HttpMessageHandler: accepts the upgrade and echoes.</summary>
static class FakeWebSocketNode
{
    /// <summary>Answers the upgrade as a node would, and echoes every message on a real socket pair.</summary>
    public static async Task<HttpResponseMessage> UpgradeAsync(string key)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var near = new TcpClient();
        await near.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var far = await listener.AcceptTcpClientAsync();
        var node = WebSocket.CreateFromStream(far.GetStream(), new WebSocketCreationOptions { IsServer = true });
        _ = Task.Run(async () =>
        {
            var buffer = new byte[1024];
            try
            {
                while (true)
                {
                    var received = await node.ReceiveAsync(buffer, CancellationToken.None);
                    if (received.MessageType == WebSocketMessageType.Close)
                    {
                        await node.CloseOutputAsync(node.CloseStatus ?? WebSocketCloseStatus.NormalClosure, node.CloseStatusDescription, CancellationToken.None);
                        break;
                    }
                    await node.SendAsync(buffer.AsMemory(0, received.Count), received.MessageType, received.EndOfMessage, CancellationToken.None);
                }
            }
            catch (Exception e) when (e is WebSocketException or IOException)
            {
            }
            finally
            {
                node.Dispose();
                far.Dispose();
            }
        });
        // RFC 6455 fixes SHA-1 for the handshake; it protects nothing.
#pragma warning disable CA5350
        var accept = Convert.ToBase64String(SHA1.HashData(System.Text.Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
#pragma warning restore CA5350
        var response = new HttpResponseMessage(HttpStatusCode.SwitchingProtocols) { Content = new Duplex(near) };
        response.Headers.Connection.Add("Upgrade");
        response.Headers.Upgrade.Add(new("websocket"));
        response.Headers.Add("Sec-WebSocket-Accept", accept);
        return response;
    }

    /// <summary>The upgraded connection as response content: readable and writable, as SocketsHttpHandler hands it over.</summary>
    sealed class Duplex(TcpClient connection) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
        protected override Stream CreateContentReadStream(CancellationToken cancellationToken) => connection.GetStream();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(connection.GetStream());
        protected override void Dispose(bool disposing)
        {
            if (disposing)
                connection.Dispose();
            base.Dispose(disposing);
        }
    }
}
