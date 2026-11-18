using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.Protocol;

/// <summary>What the app asks the agent for. The agent identifies the caller itself, from the pipe.</summary>
public sealed record AgentRequest(string Op, string UserSecretsId, string SecretsDirectory)
{
    public const string LoadUserSecrets = "usersecrets.load";
}

public enum AgentStatus
{
    Ok,
    /// <summary>The user refused the consent screen, or let it time out.</summary>
    Denied,
    Error,
}

/// <param name="Json">The secrets document, as stored; only set when <see cref="Status"/> is <see cref="AgentStatus.Ok"/>.</param>
/// <param name="RefreshAt">
/// Unix seconds: the document holds values that expire (a temporary SQL login), so load it again by
/// then. <c>null</c> when nothing in it expires.
/// </param>
public sealed record AgentReply(AgentStatus Status, string? Json = null, string? Message = null, long? RefreshAt = null);

/// <summary>
/// Wire format between the configuration provider and the tir agent: one request, one reply, each a
/// little-endian int32 length followed by that many bytes of UTF-8 JSON. Shared by both ends so
/// neither can drift.
/// </summary>
public static class AgentWire
{
    /// <summary>
    /// Per user, because pipe names are machine-wide: another account's agent must not be able to
    /// take the name first. <see cref="PipeOptions.CurrentUserOnly"/> enforces the same on connect.
    /// </summary>
    public static string PipeName => $"tiresias.usersecrets.{Environment.UserName}";

    /// <summary>A secrets document is small; anything bigger is a confused or hostile peer.</summary>
    public const int MaxMessageBytes = 1 << 20;

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(body, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxMessageBytes)
            throw new InvalidDataException($"Agent message of {length} bytes is out of range.");
        var body = new byte[length];
        await stream.ReadExactlyAsync(body, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, Json) ?? throw new InvalidDataException("Empty agent message.");
    }
}
