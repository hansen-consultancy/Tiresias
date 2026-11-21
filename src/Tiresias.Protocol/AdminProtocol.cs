using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Tiresias.Protocol;

/// <summary>
/// A request to the admin tier's service (docs/admin-tier.md). The service names the caller from the
/// pipe itself; nothing in a request says who is asking.
/// </summary>
/// <param name="Version">The protocol version the client speaks; the service refuses one it doesn't.</param>
/// <param name="Op">One of <see cref="AdminOps"/>.</param>
/// <param name="Args">The op's typed arguments; <c>null</c> or empty for an op that takes none.</param>
public sealed record AdminRequest(int Version, string Op, JsonObject? Args = null);

public enum AdminStatus
{
    Ok,
    /// <summary>Not done: the caller, the op or an argument isn't allowed. <see cref="AdminReply.Message"/> says which.</summary>
    Refused,
    Error,
}

/// <param name="Result">The op's result when <see cref="Status"/> is <see cref="AdminStatus.Ok"/>.</param>
public sealed record AdminReply(AdminStatus Status, JsonObject? Result = null, string? Message = null)
{
    public static AdminReply Ok<T>(T result) => new(AdminStatus.Ok, AdminWire.ToObject(result));

    public static AdminReply Refused(string message) => new(AdminStatus.Refused, Message: message);

    /// <summary>The result as <typeparamref name="T"/>, or <c>null</c> when the reply isn't ok.</summary>
    public T? ResultAs<T>() where T : class =>
        Status == AdminStatus.Ok && Result is not null ? Result.Deserialize<T>(AdminWire.Json) : null;
}

/// <summary>The fixed list of actions (docs/admin-tier.md, <i>Actions</i>).</summary>
public static class AdminOps
{
    public const string Status = "status";
    public const string EventsWait = "events.wait";
    public const string DecoysAdopt = "decoys.adopt";
    public const string DecoysStatus = "decoys.status";
    public const string Freeze = "freeze";
    public const string Thaw = "thaw";
    public const string DecoysRelease = "decoys.release";
    public const string LastRun = "lastrun";
    public const string Teardown = "teardown";

    public static IReadOnlyList<string> All { get; } =
        [Status, EventsWait, DecoysAdopt, DecoysStatus, Freeze, Thaw, DecoysRelease, LastRun, Teardown];
}

/// <summary>What <see cref="AdminOps.Status"/> answers: versions and which features are on, never more.</summary>
/// <param name="Version">The service's version, in the app's form ("0.2.1", "0.3.0-preview.1").</param>
public sealed record AdminStatusResult(string Version, int ProtocolVersion, AdminFeatures Features);

public sealed record AdminFeatures(bool DecoysHeld = false, bool Listening = false, bool Auditing = false);

/// <summary>
/// Wire format between the app (or tir) and the admin tier's service: the agent pipe's framing
/// (<see cref="AgentWire"/>), one request and one reply per connection.
/// </summary>
public static class AdminWire
{
    /// <summary>Machine-wide on purpose: one service serves every user, each keyed by the caller's SID.</summary>
    public const string PipeName = "tiresias.admin";

    public const int ProtocolVersion = 1;

    /// <summary>The Windows service's name; the client trusts the pipe only when its server is this service's process.</summary>
    public const string ServiceName = "TiresiasAdmin";

    public const int MaxMessageBytes = 1 << 20;

    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static Task WriteAsync<T>(Stream stream, T message, CancellationToken ct) =>
        LengthPrefixedJson.WriteAsync(stream, message, Json, ct);

    public static Task<T> ReadAsync<T>(Stream stream, CancellationToken ct) =>
        LengthPrefixedJson.ReadAsync<T>(stream, Json, MaxMessageBytes, "Admin", ct);

    internal static JsonObject ToObject<T>(T value) =>
        JsonSerializer.SerializeToNode(value, Json) as JsonObject ?? throw new ArgumentException("A result is a JSON object.", nameof(value));
}
