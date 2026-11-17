using System.Net;
using System.Text;
using Tiresias.Policy;
using Tiresias.Raven;
using Tiresias.Transport;

namespace Tiresias.Broker;

/// <summary>
/// <c>* /svc/{service}/{**path}</c> and <c>* /raven/{instance}/{**path}</c>: asks
/// <see cref="BrokerState"/> for a decision, and on allow forwards the request with the placeholder
/// swapped for the real credential: an <c>Authorization</c> header for <c>/svc</c>, a client
/// certificate for <c>/raven</c>. The path the policy checked and the path sent upstream are the
/// same raw string; nothing is decoded or normalised in between.
/// </summary>
sealed class SvcProxy(BrokerState state, IHttpClientFactory clients, RavenClients ravenClients)
{
    public const string ClientName = "upstream";

    static readonly HashSet<string> Stripped = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
        "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Host", "Authorization",
    };

    public Task HandleAsync(HttpContext context, string service) => ForwardAsync(context, "svc", service);

    public Task HandleRavenAsync(HttpContext context, string instance)
    {
        if (context.WebSockets.IsWebSocketRequest)
        {
            // Changes API and subscriptions: unsupported in v1, and said so rather than half-proxied.
            context.Response.StatusCode = StatusCodes.Status501NotImplemented;
            return Task.CompletedTask;
        }
        return ForwardAsync(context, "raven", instance);
    }

    async Task ForwardAsync(HttpContext context, string route, string service)
    {
        var request = context.Request;
        var ct = context.RequestAborted;
        var raven = route == "raven";
        var pathAndQuery = SvcPath.Remainder(DeviceSignatureMiddleware.RawTarget(context), service, route);

        // The rule's body limit needs a length; a chunked body is buffered to learn it (Kestrel's
        // request size limit still caps it).
        Stream? body = null;
        long length = 0;
        await using var buffered = new MemoryStream();
        if (request.ContentLength is { } declared)
        {
            length = declared;
            body = declared > 0 ? request.Body : null;
        }
        else if (request.Headers.TransferEncoding.Count > 0)
        {
            await request.Body.CopyToAsync(buffered, ct);
            buffered.Position = 0;
            length = buffered.Length;
            body = buffered;
        }

        var (allowed, refusal) = state.Authorize(request.Headers.Authorization, service,
            new BrokeredRequest(request.Method, pathAndQuery ?? "", length),
            request.Headers[ForwarderHeaders.ObservedProcess].FirstOrDefault() is { Length: > 0 } observed ? observed : null);
        if (refusal is not null)
        {
            await Results.Json(new RefusalBody(refusal.Reason, refusal.ElevationNeeded), statusCode: refusal.Status).ExecuteAsync(context);
            return;
        }

        using (allowed)
        {
            var target = new Uri(allowed!.Service.Upstream.AbsoluteUri.TrimEnd('/') + pathAndQuery,
                new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true });
            using var message = new HttpRequestMessage(new HttpMethod(request.Method), target);
            if (body is not null)
                message.Content = new StreamContent(body);

            // A topology body is rewritten, so it must come back uncompressed.
            var topology = raven && RavenTopology.IsTopologyPath(pathAndQuery!);
            var connectionTokens = request.Headers.Connection.SelectMany(v => (v ?? "").Split(',', StringSplitOptions.TrimEntries)).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, values) in request.Headers)
            {
                if (Stripped.Contains(name) || connectionTokens.Contains(name) || name.StartsWith("X-Tiresias-", StringComparison.OrdinalIgnoreCase)
                    || (topology && name.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase)))
                    continue;
                if (!message.Headers.TryAddWithoutValidation(name, values.ToArray()))
                    message.Content?.Headers.TryAddWithoutValidation(name, values.ToArray());
            }

            HttpMessageInvoker upstream;
            if (raven)
            {
                try
                {
                    upstream = ravenClients.For(allowed.LeaseId, allowed.Grant.SecretSlug, allowed.TakeSecret);
                }
                catch (Exception e) when (e is FormatException or System.Security.Cryptography.CryptographicException)
                {
                    allowed.Complete(StatusCodes.Status500InternalServerError, "certificate-unreadable");
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    return;
                }
            }
            else
            {
                message.Headers.TryAddWithoutValidation("Authorization", allowed.TakeSecret());
                upstream = clients.CreateClient(ClientName);
            }

            HttpResponseMessage response;
            try
            {
                response = upstream is HttpClient client
                    ? await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct)
                    : await upstream.SendAsync(message, ct);
            }
            catch (HttpRequestException)
            {
                allowed.Complete(StatusCodes.Status502BadGateway, "upstream-unreachable");
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                return;
            }

            using (response)
            {
                allowed.Complete((int)response.StatusCode);
                context.Response.StatusCode = (int)response.StatusCode;
                var rewrite = topology && response.StatusCode == HttpStatusCode.OK;
                foreach (var (name, values) in response.Headers.Concat(response.Content.Headers))
                    if (!Stripped.Contains(name) && !(rewrite && name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)))
                        context.Response.Headers[name] = values.ToArray();
                if (rewrite)
                {
                    var rewritten = RavenTopology.Rewrite(await response.Content.ReadAsStringAsync(ct), PublicBase(context, service));
                    await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(rewritten), ct);
                }
                else
                    await response.Content.CopyToAsync(context.Response.Body, ct);
            }
        }
    }

    static string PublicBase(HttpContext context, string instance)
    {
        var forwarded = context.Request.Headers[ForwarderHeaders.PublicBase].FirstOrDefault();
        var origin = Uri.TryCreate(forwarded, UriKind.Absolute, out var uri) && uri.IsLoopback && uri.Scheme is "http" or "https"
            ? uri.GetLeftPart(UriPartial.Authority)
            : $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}";
        return $"{origin}/raven/{instance}";
    }

    sealed record RefusalBody(string Reason, string? ElevationNeeded);
}

static class SvcPath
{
    /// <summary>
    /// The upstream path and query from the raw request target, e.g. <c>/svc/llm/v1/models?x=1</c> →
    /// <c>/v1/models?x=1</c>. <c>null</c> when the target doesn't literally start with the routed
    /// service (an encoded service segment, say), which the caller then refuses as a suspicious path.
    /// </summary>
    public static string? Remainder(string rawTarget, string service, string route = "svc")
    {
        var prefix = "/" + route + "/" + service;
        if (!rawTarget.StartsWith(prefix, StringComparison.Ordinal))
            return null;
        var rest = rawTarget[prefix.Length..];
        return rest.Length == 0 ? "/"
            : rest[0] == '/' ? rest
            : rest[0] == '?' ? "/" + rest
            : null;
    }
}
