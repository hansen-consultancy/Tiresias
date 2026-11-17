using System.Text.Json;

namespace Tiresias.Trust;

/// <summary>
/// The one byte form of a link, written by hand in a fixed field order and never by a reflection
/// serializer whose order could change. The form without <c>sigs</c> is the <b>signed</b> form; the
/// full form is what <see cref="TrustChain.Hash"/> covers, so <c>prev</c> and the pinned genesis hash
/// commit to the signatures too. Another implementation must reproduce these bytes exactly.
/// </summary>
/// <remarks>
/// Parsing ignores unknown fields; that is safe because nothing is ever verified or hashed from
/// the received bytes, only from this writer's re-serialization.
/// </remarks>
public static class TrustLinkJson
{
    public static byte[] Write(TrustLink link, bool withSignatures)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
            WriteLink(writer, link, withSignatures);
        return buffer.ToArray();
    }

    public static byte[] WriteChain(IEnumerable<TrustLink> links)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();
            foreach (var link in links)
                WriteLink(writer, link, withSignatures: true);
            writer.WriteEndArray();
        }
        return buffer.ToArray();
    }

    /// <returns>The links, or <c>null</c> when the JSON is not a chain.</returns>
    public static TrustLink[]? ParseChain(ReadOnlySpan<byte> json)
    {
        try
        {
            var reader = new Utf8JsonReader(json);
            using var doc = JsonDocument.ParseValue(ref reader);
            return doc.RootElement.EnumerateArray().Select(ParseLink).ToArray();
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    static void WriteLink(Utf8JsonWriter w, TrustLink link, bool withSignatures)
    {
        w.WriteStartObject();
        w.WriteNumber("seq", link.Seq);
        w.WriteString("prev", link.Prev);
        w.WriteNumber("time", link.Time.ToUnixTimeSeconds());
        w.WriteString("kind", Kind(link.Body));
        w.WriteStartObject("body");
        switch (link.Body)
        {
            case Genesis g:
                w.WriteString("tenant", g.Tenant);
                w.WriteString("admin", g.Admin);
                WriteDevice(w, "device", g.Device);
                WriteDevice(w, "paperKey", g.PaperKey);
                WritePolicy(w, g.Policy);
                break;
            case AddUser u:
                w.WriteString("user", u.User);
                w.WriteBoolean("admin", u.Admin);
                WriteDevice(w, "device", u.Device);
                WriteDevice(w, "paperKey", u.PaperKey);
                break;
            case AddDevice d:
                w.WriteString("user", d.User);
                WriteDevice(w, "device", d.Device);
                break;
            case RevokeDevice r:
                w.WriteString("deviceId", r.DeviceId);
                break;
            case RemoveUser r:
                w.WriteString("user", r.User);
                break;
            case AddBroker b:
                w.WriteString("broker", b.Broker);
                w.WriteBase64String("key", b.PublicKey);
                break;
            case SetPolicy p:
                WritePolicy(w, p.Policy);
                break;
        }
        w.WriteEndObject();
        if (withSignatures)
        {
            w.WriteStartArray("sigs");
            foreach (var s in link.Signatures)
            {
                w.WriteStartObject();
                w.WriteString("device", s.DeviceId);
                w.WriteBase64String("sig", s.Signature);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }
        w.WriteEndObject();
    }

    static void WriteDevice(Utf8JsonWriter w, string name, DeviceRef? device)
    {
        if (device is null)
        {
            w.WriteNull(name);
            return;
        }
        w.WriteStartObject(name);
        w.WriteString("id", device.Id);
        w.WriteBase64String("key", device.PublicKey);
        w.WriteBoolean("paper", device.Paper);
        w.WriteEndObject();
    }

    static void WritePolicy(Utf8JsonWriter w, TrustPolicy policy)
    {
        w.WriteStartObject("policy");
        w.WriteNumber("adminThreshold", policy.AdminThreshold);
        w.WriteEndObject();
    }

    /// <summary>The spec's name for the link kind, as written in <c>kind</c>.</summary>
    public static string Kind(LinkBody body) => body switch
    {
        Genesis => "genesis",
        AddUser => "add-user",
        AddDevice => "add-device",
        RevokeDevice => "revoke-device",
        RemoveUser => "remove-user",
        AddBroker => "add-broker",
        SetPolicy => "set-policy",
        _ => throw new ArgumentOutOfRangeException(nameof(body)),
    };

    static TrustLink ParseLink(JsonElement e)
    {
        var b = e.GetProperty("body");
        LinkBody body = e.GetProperty("kind").GetString() switch
        {
            "genesis" => new Genesis(Str(b, "tenant"), Str(b, "admin"), Device(b, "device")!, Device(b, "paperKey")!, Policy(b)),
            "add-user" => new AddUser(Str(b, "user"), b.GetProperty("admin").GetBoolean(), Device(b, "device")!, Device(b, "paperKey")),
            "add-device" => new AddDevice(Str(b, "user"), Device(b, "device")!),
            "revoke-device" => new RevokeDevice(Str(b, "deviceId")),
            "remove-user" => new RemoveUser(Str(b, "user")),
            "add-broker" => new AddBroker(Str(b, "broker"), b.GetProperty("key").GetBytesFromBase64()),
            "set-policy" => new SetPolicy(Policy(b)),
            var kind => throw new FormatException($"Unknown link kind '{kind}'."),
        };
        var sigs = e.GetProperty("sigs").EnumerateArray()
            .Select(s => new LinkSignature(Str(s, "device"), s.GetProperty("sig").GetBytesFromBase64()))
            .ToArray();
        return new(e.GetProperty("seq").GetInt64(), Str(e, "prev"), DateTimeOffset.FromUnixTimeSeconds(e.GetProperty("time").GetInt64()), body, sigs);
    }

    static string Str(JsonElement e, string name) =>
        e.GetProperty(name).GetString() ?? throw new FormatException($"'{name}' is null.");

    static DeviceRef? Device(JsonElement e, string name)
    {
        var d = e.GetProperty(name);
        if (d.ValueKind == JsonValueKind.Null)
            return null;
        return new(Str(d, "id"), d.GetProperty("key").GetBytesFromBase64(), d.GetProperty("paper").GetBoolean());
    }

    static TrustPolicy Policy(JsonElement e) => new(e.GetProperty("policy").GetProperty("adminThreshold").GetInt32());
}
