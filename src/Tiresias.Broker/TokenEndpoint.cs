using System.Net.Http.Headers;
using System.Text.Json;
using Tiresias.GitHub;

namespace Tiresias.Broker;

public sealed record InstallationToken(string Token, DateTimeOffset ExpiresAt);

/// <summary>Exchanges a GitHub App JWT for an installation token. The one network call of <c>/token</c>, behind a seam for tests.</summary>
public interface IGitHubInstallationTokens
{
    /// <returns><c>null</c> when GitHub refused.</returns>
    Task<InstallationToken?> CreateAsync(Uri api, long installationId, string appJwt, CancellationToken ct);
}

sealed class GitHubInstallationTokens(IHttpClientFactory clients) : IGitHubInstallationTokens
{
    public async Task<InstallationToken?> CreateAsync(Uri api, long installationId, string appJwt, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(api, $"/app/installations/{installationId}/access_tokens"));
        message.Headers.Authorization = new("Bearer", appJwt);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        message.Headers.UserAgent.Add(new ProductInfoHeaderValue("Tiresias", "1"));
        message.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        using var response = await clients.CreateClient(SvcProxy.ClientName).SendAsync(message, ct);
        if (!response.IsSuccessStatusCode)
            return null;
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return new(body.RootElement.GetProperty("token").GetString()!, body.RootElement.GetProperty("expires_at").GetDateTimeOffset());
    }
}

/// <summary>
/// <c>POST /token/{service}</c>, device-signed: an installation token for a GitHub App service.
/// The app's private key signs a JWT here and is zeroed; only the token, scoped to the installation
/// and dead within the hour, goes back to the device.
/// </summary>
sealed class TokenEndpoint(BrokerState state, IGitHubInstallationTokens github, TimeProvider time)
{
    public async Task<IResult> HandleAsync(HttpContext context, string service)
    {
        var (allowed, refusal) = state.AuthorizeToken(service, (string)context.Items[DeviceSignatureMiddleware.DeviceItem]!);
        if (refusal is not null)
            return Results.Json(new { refusal.Reason, refusal.ElevationNeeded }, statusCode: refusal.Status);

        using (allowed)
        {
            if (GitHubAppSecret.Parse(System.Text.Encoding.UTF8.GetBytes(allowed!.TakeSecret())) is not { } app)
            {
                allowed.Complete(StatusCodes.Status500InternalServerError, "secret-not-github-app");
                return Results.Json(new { reason = "secret-not-github-app" }, statusCode: StatusCodes.Status500InternalServerError);
            }

            var jwt = GitHubAppJwt.Create(app.AppId, app.PrivateKeyPem, time.GetUtcNow());
            InstallationToken? token;
            try
            {
                token = await github.CreateAsync(allowed.Service.Upstream, app.InstallationId, jwt, context.RequestAborted);
            }
            catch (HttpRequestException)
            {
                token = null;
            }
            if (token is null)
            {
                allowed.Complete(StatusCodes.Status502BadGateway, "github-refused");
                return Results.Json(new { reason = "github-refused" }, statusCode: StatusCodes.Status502BadGateway);
            }
            allowed.Complete(StatusCodes.Status200OK, $"until {token.ExpiresAt:O}");
            return Results.Ok(new { token = token.Token, expiresAt = token.ExpiresAt });
        }
    }
}
