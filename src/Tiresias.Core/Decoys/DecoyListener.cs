using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Tiresias.Decoys;

/// <summary>
/// A use of a decoy: what was presented, on which endpoint, and the local process that connected.
/// <paramref name="ProcessId"/> is <c>null</c> when the connection's owner couldn't be found.
/// </summary>
public sealed record DecoyHit(DecoyUse Use, string Endpoint, int? ProcessId, string? Program, DateTimeOffset At);

/// <summary>
/// The decoys' endpoints on loopback: an HTTP port (the admin URL, the OpenAI base URL, the RavenDB
/// URL) and a SQL Server port. Every connection is a hit, since only a decoy names these ports; the
/// process is identified as soon as it connects, while the connection is still there. Each caller
/// gets the refusal the real service gives a bad credential (401, login failed for user), so it
/// learns nothing.
/// </summary>
public sealed class DecoyListener : IAsyncDisposable
{
    readonly DecoySet set;
    readonly Func<IPEndPoint, int, (int Pid, string? Program)?> identify;
    readonly TimeProvider time;
    readonly CancellationTokenSource stop = new();
    readonly List<TcpListener> listeners = [];
    readonly List<Task> running = [];

    /// <param name="identify">The process owning a loopback connection, from the client's end point and the server's port.</param>
    public DecoyListener(DecoySet set, Func<IPEndPoint, int, (int Pid, string? Program)?> identify, TimeProvider time)
    {
        this.set = set;
        this.identify = identify;
        this.time = time;
    }

    /// <summary>Raised once per connection, after the caller has been answered (or gave up). Never carries a value.</summary>
    public event Action<DecoyHit>? Hit;

    /// <exception cref="SocketException">A port is taken.</exception>
    public void Start()
    {
        foreach (var (port, serve) in new (int, Func<Stream, CancellationToken, Task<(DecoyUse, string)>>)[] { (set.HttpPort, ServeHttpAsync), (set.SqlPort, ServeSqlAsync) })
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listeners.Add(listener);
            running.Add(AcceptAsync(listener, port, serve));
        }
    }

    async Task AcceptAsync(TcpListener listener, int port, Func<Stream, CancellationToken, Task<(DecoyUse, string)>> serve)
    {
        while (!stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(stop.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }
            _ = Task.Run(() => HandleAsync(client, port, serve));
        }
    }

    async Task HandleAsync(TcpClient client, int port, Func<Stream, CancellationToken, Task<(DecoyUse, string)>> serve)
    {
        using (client)
        {
            var caller = client.Client.RemoteEndPoint is IPEndPoint remote ? identify(remote, port) : null;
            var (use, endpoint) = (DecoyUse.Connected, port == set.SqlPort ? "SQL Server" : "HTTP");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                (use, endpoint) = await serve(client.GetStream(), timeout.Token);
            }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or InvalidDataException or ObjectDisposedException)
            {
                // A caller that hangs up or speaks something else is still a caller.
            }
            Hit?.Invoke(new(use, endpoint, caller?.Pid, caller?.Program, time.GetUtcNow()));
        }
    }

    async Task<(DecoyUse, string)> ServeHttpAsync(Stream stream, CancellationToken ct)
    {
        var head = await ReadHeadAsync(stream, ct);
        var request = head.Split("\r\n", 2)[0].Split(' ');
        // Only the path: a token in the query string stays out of the record.
        var endpoint = request.Length >= 2 ? $"HTTP {request[0]} {request[1].Split('?')[0]}" : "HTTP";
        var use = set.Recognise(head) ?? DecoyUse.Connected;
        var body = request.Length >= 2 && request[1].StartsWith("/v1", StringComparison.Ordinal)
            ? """{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}"""
            : """{"error":"invalid_token"}""";
        var reply = $"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
        await stream.WriteAsync(Encoding.UTF8.GetBytes(reply), ct);
        return (use, endpoint);
    }

    /// <summary>The request line and headers, up to 16 KB.</summary>
    static async Task<string> ReadHeadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[16 * 1024];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), ct);
            if (read == 0)
                break;
            length += read;
            if (buffer.AsSpan(0, length).IndexOf("\r\n\r\n"u8) >= 0)
                break;
        }
        return Encoding.Latin1.GetString(buffer, 0, length);
    }

    async Task<(DecoyUse, string)> ServeSqlAsync(Stream stream, CancellationToken ct)
    {
        var use = DecoyUse.Connected;
        for (var message = 0; message < 4; message++)
        {
            var (type, body) = await ReadPacketAsync(stream, ct);
            if (type == DecoyTds.PreLogin)
                await stream.WriteAsync(DecoyTds.PreLoginResponse(), ct);
            else if (type == DecoyTds.Login7)
            {
                var login = DecoyTds.ReadLogin(body);
                use = set.Recognise(login?.Password) ?? DecoyUse.Connected;
                await stream.WriteAsync(DecoyTds.LoginFailed(login?.User ?? ""), ct);
                break;
            }
            else
                break;
        }
        return (use, "SQL Server");
    }

    /// <summary>One TDS packet; a login fits in one.</summary>
    static async Task<(byte Type, byte[] Body)> ReadPacketAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[8];
        await stream.ReadExactlyAsync(header, ct);
        var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
        if (length < 8)
            throw new InvalidDataException("Not a TDS packet.");
        var body = new byte[length - 8];
        await stream.ReadExactlyAsync(body, ct);
        return (header[0], body);
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        foreach (var listener in listeners)
            listener.Stop();
        try
        {
            await Task.WhenAll(running);
        }
        catch (OperationCanceledException)
        {
        }
        stop.Dispose();
    }
}
