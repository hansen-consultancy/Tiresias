using System.Buffers.Binary;
using System.Text.Json;

namespace Tiresias.Protocol;

/// <summary>
/// The framing both pipes speak (<see cref="AgentWire"/>, <see cref="AdminWire"/>): a little-endian
/// int32 length, then that many bytes of UTF-8 JSON.
/// </summary>
static class LengthPrefixedJson
{
    public static async Task WriteAsync<T>(Stream stream, T message, JsonSerializerOptions options, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, options);
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(body, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <param name="peer">Names the pipe in errors: "Agent message of 0 bytes is out of range."</param>
    public static async Task<T> ReadAsync<T>(Stream stream, JsonSerializerOptions options, int maxBytes, string peer, CancellationToken ct)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxBytes)
            throw new InvalidDataException($"{peer} message of {length} bytes is out of range.");
        var body = new byte[length];
        await stream.ReadExactlyAsync(body, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, options) ?? throw new InvalidDataException($"Empty {peer.ToLowerInvariant()} message.");
    }
}
