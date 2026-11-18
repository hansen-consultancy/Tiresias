using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Tiresias.Agent;

/// <summary>
/// Asks the broker, through the forwarder (or the solo broker), for a lease's temporary SQL login,
/// authenticated by a placeholder for the service like any other brokered request.
/// </summary>
public static class SqlLogin
{
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <returns>The login as a connection string.</returns>
    /// <exception cref="InvalidOperationException">The broker refused, with its reason.</exception>
    public static async Task<string> RequestAsync(string service, string grant, string placeholder, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri(PlaceholderMinter.Endpoint, $"/sql/{Uri.EscapeDataString(service)}/{Uri.EscapeDataString(grant)}/login"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", placeholder);
        using var response = await Http.SendAsync(request, ct);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        if (!response.IsSuccessStatusCode)
        {
            var reason = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("reason", out var r) ? r.GetString() : null;
            throw new InvalidOperationException($"{service}: no SQL login ({(int)response.StatusCode} {reason ?? response.ReasonPhrase}).");
        }
        return body.GetProperty("connectionString").GetString()!;
    }
}
