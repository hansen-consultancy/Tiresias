using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.AdminTier;

/// <summary>
/// One line of the service's action log, <c>%ProgramData%\Tiresias\Admin\actions.jsonl</c>: every
/// request, with who asked and what came of it. Never an argument or a value: the op is one of the
/// fixed list or <c>unknown</c>, so a caller's text never reaches the log.
/// </summary>
/// <param name="V">The line's format version.</param>
/// <param name="Op">The op, or <c>unknown</c>.</param>
/// <param name="CallerSid">The caller's user SID; <c>null</c> when it couldn't be read.</param>
/// <param name="Image">The caller's image path, from its process.</param>
/// <param name="Result"><c>requested</c> before an authorized change, then <c>ok</c>, <c>refused</c> or <c>error</c>.</param>
/// <param name="ActingFor">The session user whose state an authorized operation addresses.</param>
/// <param name="Reason">Why it was refused or failed, in the service's own words.</param>
public sealed record AdminAction(
    int V,
    DateTimeOffset At,
    string Op,
    string? CallerSid,
    int? Pid,
    string? Image,
    string Result,
    string? Reason,
    string? ActingFor = null)
{
    public const int Format = 1;

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static AdminAction Of(DateTimeOffset at, string? op, AdminCaller? caller, int? pid, string? image, string result, string? reason, string? actingFor = null) =>
        new(Format, at, AdminCallerPolicy.KnownOp(op) ?? "unknown", caller?.UserSid, pid, image, result, reason, actingFor);

    /// <summary>The record as one JSON line, without the newline.</summary>
    public string ToLine() => JsonSerializer.Serialize(this, Json);
}
