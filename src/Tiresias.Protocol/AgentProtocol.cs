using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.Protocol;

/// <summary>What the app asks the agent for. The agent identifies the caller itself, from the pipe.</summary>
/// <param name="SecretsDirectory">
/// For <see cref="LoadUserSecrets"/>, the project's user-secrets folder. For
/// <see cref="LoadEnvironment"/>, the folder the app runs in, which picks the folder sets.
/// </param>
/// <param name="Present">
/// For <see cref="LoadEnvironment"/>: the variable names the process already has, which it is not
/// given again (and the user is not asked about). An agent that predates the op ignores it.
/// </param>
public sealed record AgentRequest(string Op, string UserSecretsId, string SecretsDirectory, IReadOnlyList<string>? Present = null)
{
    public const string LoadUserSecrets = "usersecrets.load";

    /// <summary>
    /// The sealed environment variables marked for configuration, for the app asking. The reply's
    /// <see cref="AgentReply.Json"/> is an object of variable names to values.
    /// </summary>
    public const string LoadEnvironment = "environment.load";

    public static AgentRequest ForEnvironment(string directory, IReadOnlyList<string> present) =>
        new(LoadEnvironment, "", directory, present);
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

    public static Task WriteAsync<T>(Stream stream, T message, CancellationToken ct) =>
        LengthPrefixedJson.WriteAsync(stream, message, Json, ct);

    public static Task<T> ReadAsync<T>(Stream stream, CancellationToken ct) =>
        LengthPrefixedJson.ReadAsync<T>(stream, Json, MaxMessageBytes, "Agent", ct);
}
