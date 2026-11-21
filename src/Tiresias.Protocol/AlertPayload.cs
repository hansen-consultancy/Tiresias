using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.Protocol;

/// <summary>How serious an alert is (docs/alerts.md, <i>Events</i>). Ordered: a sink's threshold drops anything below it.</summary>
public enum AlertSeverity
{
    Info,
    Warning,
    High,
    Critical,
}

/// <summary>
/// One alert as it leaves the machine: <c>tiresias.alert/v1</c> (docs/alerts.md, <i>The payload</i>). The
/// webhook's body as is, and what every other sink formats from. There is no free-text field and no
/// dictionary on purpose: a field that isn't on this record can't leave. <c>AlertPayloadTests</c> pins the
/// property list, so adding one is a decision, not an accident.
/// </summary>
/// <param name="Id">A ULID per delivery, also the <c>Idempotency-Key</c>.</param>
/// <param name="Title">From the event table, never from the event's own data.</param>
/// <param name="Machine">The label the user chose; never the host name.</param>
/// <param name="At">When the first occurrence this delivery stands for happened.</param>
/// <param name="Count">Occurrences this delivery stands for.</param>
/// <param name="Key"><c>event:</c> plus 16 hex of a keyed HMAC over the subject: groups repeats, reveals nothing.</param>
/// <param name="Detail">Trusted sinks only; <c>null</c> (absent from the JSON) on a public sink.</param>
public sealed record AlertPayload(
    string Id,
    string Event,
    AlertSeverity Severity,
    string Title,
    string Machine,
    DateTimeOffset At,
    int Count,
    string Key,
    TrustedDetail? Detail)
{
    [JsonPropertyOrder(-1)]
    public string Schema => AlertWire.Schema;
}

/// <summary>
/// What a trusted sink learns beyond the public fields: names and paths, never a value, a token, a
/// command line or key material. Empty lists are <c>null</c> so they stay out of the JSON.
/// </summary>
/// <param name="Program">The full path of the program the event is about.</param>
/// <param name="Parents">The processes that started it, nearest first, as paths or file names.</param>
/// <param name="What">What was touched, e.g. which decoy ("the decoy admin token").</param>
/// <param name="Names">Secret or variable names.</param>
/// <param name="Findings">Finding titles.</param>
public sealed record TrustedDetail(
    string? Program = null,
    int? ProcessId = null,
    IReadOnlyList<string>? Parents = null,
    string? What = null,
    string? Service = null,
    IReadOnlyList<string>? Names = null,
    IReadOnlyList<string>? Findings = null);

/// <summary>Reads and writes <see cref="AlertPayload"/> as <c>tiresias.alert/v1</c> JSON.</summary>
public static class AlertWire
{
    public const string Schema = "tiresias.alert/v1";

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase), new UtcConverter() },
    };

    public static byte[] Serialize(AlertPayload payload) => JsonSerializer.SerializeToUtf8Bytes(payload, Json);

    /// <summary>Reads a payload, refusing any schema but <see cref="Schema"/>.</summary>
    /// <exception cref="InvalidDataException">Not a <c>tiresias.alert/v1</c> document.</exception>
    public static AlertPayload Parse(ReadOnlySpan<byte> json)
    {
        using (var document = JsonDocument.Parse(json.ToArray()))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("schema", out var schema)
                || schema.ValueKind != JsonValueKind.String
                || schema.GetString() != Schema)
                throw new InvalidDataException($"Not a {Schema} document.");
        }
        return JsonSerializer.Deserialize<AlertPayload>(json, Json) ?? throw new InvalidDataException($"Not a {Schema} document.");
    }

    /// <summary>UTC with a <c>Z</c>, as the format promises, whatever offset the value carries.</summary>
    sealed class UtcConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            DateTimeOffset.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime();

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture));
    }
}
