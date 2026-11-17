using System.Net;
using System.Text.Json;
using Tiresias.Transport;
using NSec.Cryptography;

namespace Tiresias.Agent;

/// <summary>The broker's answer: the status, and the JSON body when there was one.</summary>
public sealed record BrokerResponse(HttpStatusCode Status, JsonElement? Body)
{
    public bool Ok => (int)Status is >= 200 and < 300;

    /// <summary>The broker's refusal reason, e.g. <c>no-lease</c> or <c>elevation-required</c>, for messages.</summary>
    public string Describe() =>
        Body is { ValueKind: JsonValueKind.Object } body && body.TryGetProperty("reason", out var reason)
            ? $"{(int)Status} {reason.GetString()}"
              + (body.TryGetProperty("elevationNeeded", out var e) && e.ValueKind == JsonValueKind.String ? $": {e.GetString()}" : "")
              + (body.TryGetProperty("problems", out var p) && p.ValueKind == JsonValueKind.Array ? $" ({string.Join(" ", p.EnumerateArray().Select(x => x.GetString()))})" : "")
            : $"{(int)Status} {Status}";
}

/// <summary>
/// Management calls to the broker, each signed with the device key per <see cref="RequestSignature"/>
/// over the exact request target the broker will see. Owns the device key it is given.
/// </summary>
public sealed class BrokerClient(BrokerPin broker, string deviceId, Key deviceKey) : IDisposable
{
    readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>A client for <paramref name="broker"/> signing as this device, with the selected tenant's settings.</summary>
    public static BrokerClient For(BrokerPin broker) => new(broker, KeyringStore.Settings.DeviceId, KeyringStore.LoadOrCreateDeviceKey());

    public async Task<BrokerResponse> PostAsync(string endpoint, object? body = null)
    {
        var bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, JsonSerializerOptions.Web);
        var (status, text) = await SendAsync(HttpMethod.Post, endpoint, bytes);
        return new(status, ParseJson(System.Text.Encoding.UTF8.GetString(text)));
    }

    /// <summary>A signed GET, returning the body as sent, for callers that verify it themselves.</summary>
    public Task<(HttpStatusCode Status, byte[] Body)> GetAsync(string endpoint) => SendAsync(HttpMethod.Get, endpoint, []);

    async Task<(HttpStatusCode, byte[])> SendAsync(HttpMethod method, string endpoint, byte[] bytes)
    {
        var uri = new Uri(broker.Url, endpoint);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        using var message = new HttpRequestMessage(method, uri);
        if (method == HttpMethod.Post)
        {
            message.Content = new ByteArrayContent(bytes);
            message.Content.Headers.ContentType = new("application/json");
        }
        message.Headers.Add(RequestSignature.DeviceHeader, deviceId);
        message.Headers.Add(RequestSignature.TimestampHeader, timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        message.Headers.Add(RequestSignature.SignatureHeader,
            Convert.ToBase64String(RequestSignature.Sign(deviceKey, method.Method, uri.PathAndQuery, timestamp, bytes)));

        using var response = await http.SendAsync(message);
        return (response.StatusCode, await response.Content.ReadAsByteArrayAsync());
    }

    static JsonElement? ParseJson(string text)
    {
        try
        {
            return text.Length == 0 ? null : JsonDocument.Parse(text).RootElement.Clone();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public void Dispose()
    {
        http.Dispose();
        deviceKey.Dispose();
    }
}
