using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.Protocol;

/// <summary>
/// <c>tir-remote</c> in a devcontainer asking the agent on the host for sealed variables, over
/// HTTP through Docker Desktop's <c>host.docker.internal</c> relay. The ticket goes in the
/// <c>Authorization</c> header, never in the body.
/// </summary>
/// <param name="Names">The variables wanted; <c>null</c> for every one sealed for the devcontainer's folder.</param>
public sealed record DevcontainerRequest(IReadOnlyList<string>? Names = null, int V = DevcontainerWire.Version);

/// <param name="Variables">For an approved request: the values or placeholders, by name, with each placeholder's base-URL variable.</param>
/// <param name="Message">Why nothing came, or which variables were left out. Never a value.</param>
public sealed record DevcontainerReply(bool Approved, IReadOnlyDictionary<string, string>? Variables = null, string? Message = null);

public static class DevcontainerWire
{
    public const int Version = 1;

    /// <summary>The agent's loopback port. The forwarder has 7781 and the solo broker 7780.</summary>
    public const int Port = 7782;

    /// <summary>Where a container reaches the host's loopback through Docker Desktop.</summary>
    public const string Host = "host.docker.internal";

    public const string EnvironmentPath = "/devcontainer/env";

    /// <summary>The variable <c>remoteEnv</c> hands the ticket in, as <c>"${localEnv:TIRESIAS_TICKET}"</c>.</summary>
    public const string TicketVariable = "TIRESIAS_TICKET";

    /// <summary>The <c>Authorization</c> scheme: <c>Tiresias &lt;ticket&gt;</c>.</summary>
    public const string Scheme = "Tiresias";

    /// <summary>A request is a list of names: anything bigger is a confused or hostile peer.</summary>
    public const int MaxRequestBytes = 16 * 1024;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>The ticket in an <c>Authorization</c> header value, or <c>null</c> for any other shape.</summary>
    public static string? Ticket(string? authorization) =>
        authorization is { } value && value.StartsWith(Scheme + " ", StringComparison.Ordinal) && value[(Scheme.Length + 1)..].Trim() is { Length: > 0 } ticket
            ? ticket
            : null;
}
