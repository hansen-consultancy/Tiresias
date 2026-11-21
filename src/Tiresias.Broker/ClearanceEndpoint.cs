using System.Security.Cryptography;
using System.Text.Json;

namespace Tiresias.Broker;

/// <summary>
/// <c>GET /clearance/{service}</c>, device-signed: who RavenDB says a service's certificate is.
/// The broker calls <c>/certificates/whoami</c> with the certificate, as the proxy would, and
/// relays only the clearance and the databases with their access. Never the certificate, its
/// thumbprint or anything else whoami returns.
/// </summary>
sealed class ClearanceEndpoint(BrokerState state, RavenClients ravenClients)
{
    public async Task<IResult> HandleAsync(HttpContext context, string service)
    {
        var (allowed, refusal) = state.AuthorizeClearance(service, (string)context.Items[DeviceSignatureMiddleware.DeviceItem]!);
        if (refusal is not null)
            return Results.Json(new { refusal.Reason, refusal.ElevationNeeded }, statusCode: refusal.Status);

        using (allowed)
        {
            HttpMessageInvoker upstream;
            try
            {
                upstream = ravenClients.For(allowed!.LeaseId, allowed.Grant.SecretSlug, allowed.TakeSecret);
            }
            catch (Exception e) when (e is FormatException or CryptographicException)
            {
                allowed!.Complete(StatusCodes.Status500InternalServerError, "certificate-unreadable");
                return Results.Json(new { reason = "certificate-unreadable" }, statusCode: StatusCodes.Status500InternalServerError);
            }

            using var message = new HttpRequestMessage(HttpMethod.Get, new Uri(allowed.Service.Upstream.AbsoluteUri.TrimEnd('/') + "/certificates/whoami"));
            Clearance? clearance;
            try
            {
                using var response = await upstream.SendAsync(message, context.RequestAborted);
                clearance = response.IsSuccessStatusCode ? Clearance.Parse(await response.Content.ReadAsStringAsync(context.RequestAborted)) : null;
            }
            catch (HttpRequestException)
            {
                clearance = null;
            }
            if (clearance is null)
            {
                allowed.Complete(StatusCodes.Status502BadGateway, "whoami-unanswered");
                return Results.Json(new { reason = "whoami-unanswered" }, statusCode: StatusCodes.Status502BadGateway);
            }
            allowed.Complete(StatusCodes.Status200OK, clearance.Level);
            return Results.Ok(new { clearance = clearance.Level, databases = clearance.Databases });
        }
    }

    /// <summary>The two fields of RavenDB's whoami answer that are relayed.</summary>
    internal sealed record Clearance(string Level, IReadOnlyDictionary<string, string> Databases)
    {
        /// <returns><c>null</c> when the body isn't a whoami answer.</returns>
        public static Clearance? Parse(string body)
        {
            try
            {
                using var json = JsonDocument.Parse(body);
                if (json.RootElement.ValueKind != JsonValueKind.Object
                    || !json.RootElement.TryGetProperty("SecurityClearance", out var level) || level.ValueKind != JsonValueKind.String)
                    return null;
                var databases = new SortedDictionary<string, string>(StringComparer.Ordinal);
                if (json.RootElement.TryGetProperty("Permissions", out var permissions) && permissions.ValueKind == JsonValueKind.Object)
                    foreach (var database in permissions.EnumerateObject())
                        databases[database.Name] = database.Value.ValueKind == JsonValueKind.String ? database.Value.GetString()! : "";
                return new(level.GetString()!, databases);
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }
}
