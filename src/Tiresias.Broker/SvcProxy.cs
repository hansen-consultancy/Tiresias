using System.Net;
using System.Net.WebSockets;
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
/// <para>
/// A <c>/raven</c> request may carry its placeholder as the first path segment instead
/// (<see cref="RavenPath"/>), and a WebSocket request (the Changes API) is a tunnel to the node,
/// checked by policy as method <c>WEBSOCKET</c>, so only a grant that lists it opens one.
/// </para>
/// </summary>
sealed class SvcProxy(BrokerState state, IHttpClientFactory clients, RavenClients ravenClients)
{
    public const string ClientName = "upstream";

    static readonly HashSet<string> Stripped = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
        "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Host", "Authorization",
    };

    /// <summary>The policy method of a WebSocket request: opaque after the handshake, so a grant opts in by name.</summary>
    public const string WebSocketMethod = "WEBSOCKET";

    public Task HandleAsync(HttpContext context, string service) =>
        ForwardAsync(context, "svc", service, SvcPath.Remainder(DeviceSignatureMiddleware.RawTarget(context), service),
            context.Request.Headers.Authorization, publicBase: null);

    public Task HandleRavenAsync(HttpContext context, string instance)
    {
        var remainder = SvcPath.Remainder(DeviceSignatureMiddleware.RawTarget(context), instance, "raven");
        var pathAndQuery = remainder;
        string? authorization = context.Request.Headers.Authorization;
        var publicBase = PublicBase(context, instance);
        if (remainder is not null && RavenPath.Split(remainder) is ({ } placeholder, var rest))
        {
            // The node URL the client learns keeps the placeholder, so its next request carries it too.
            pathAndQuery = rest;
            authorization = $"Bearer {placeholder}";
            publicBase = $"{publicBase}/{placeholder}";
        }
        return context.WebSockets.IsWebSocketRequest
            ? TunnelAsync(context, instance, pathAndQuery, authorization)
            : ForwardAsync(context, "raven", instance, pathAndQuery, authorization, publicBase);
    }

    async Task ForwardAsync(HttpContext context, string route, string service, string? pathAndQuery, string? authorization, string? publicBase)
    {
        var request = context.Request;
        var ct = context.RequestAborted;
        var raven = route == "raven";

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

        var (allowed, refusal) = state.Authorize(authorization, service, new BrokeredRequest(request.Method, pathAndQuery ?? "", length), Observed(context));
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
                    var rewritten = RavenTopology.Rewrite(await response.Content.ReadAsStringAsync(ct), publicBase!);
                    await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(rewritten), ct);
                }
                else
                    await response.Content.CopyToAsync(context.Response.Body, ct);
            }
        }
    }

    /// <summary>
    /// The Changes API: a WebSocket to the node, opened with the lease's client certificate and
    /// relayed until either side closes or the lease ends. Audited when it opens and when it closes,
    /// with the bytes moved; what crosses it is not inspected.
    /// </summary>
    async Task TunnelAsync(HttpContext context, string instance, string? pathAndQuery, string? authorization)
    {
        var (allowed, refusal) = state.Authorize(authorization, instance, new BrokeredRequest(WebSocketMethod, pathAndQuery ?? "", 0), Observed(context));
        if (refusal is not null)
        {
            await Results.Json(new RefusalBody(refusal.Reason, refusal.ElevationNeeded), statusCode: refusal.Status).ExecuteAsync(context);
            return;
        }

        using (allowed)
        {
            var upstream = allowed!.Service.Upstream;
            var target = new Uri((upstream.Scheme == Uri.UriSchemeHttps ? "wss" : "ws") + upstream.AbsoluteUri[upstream.Scheme.Length..].TrimEnd('/') + pathAndQuery,
                new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true });
            HttpMessageInvoker client;
            try
            {
                client = ravenClients.For(allowed.LeaseId, allowed.Grant.SecretSlug, allowed.TakeSecret);
            }
            catch (Exception e) when (e is FormatException or System.Security.Cryptography.CryptographicException)
            {
                allowed.Complete(StatusCodes.Status500InternalServerError, "certificate-unreadable");
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                return;
            }

            using var node = new ClientWebSocket();
            node.Options.CollectHttpResponseDetails = true;
            foreach (var protocol in context.WebSockets.WebSocketRequestedProtocols)
                node.Options.AddSubProtocol(protocol);
            try
            {
                await node.ConnectAsync(target, client, context.RequestAborted);
            }
            catch (WebSocketException)
            {
                // The node answered something other than 101 (its status is passed on), or didn't answer.
                var status = node.HttpStatusCode is var code and not 0 ? (int)code : StatusCodes.Status502BadGateway;
                allowed.Complete(status, status == StatusCodes.Status502BadGateway ? "upstream-unreachable" : "upstream-refused-websocket");
                context.Response.StatusCode = status;
                return;
            }

            using var local = await context.WebSockets.AcceptWebSocketAsync(node.SubProtocol);
            allowed.Complete(StatusCodes.Status101SwitchingProtocols);
            var leaseEnding = ravenClients.Ending(allowed.LeaseId);
            using var ending = CancellationTokenSource.CreateLinkedTokenSource(leaseEnding, context.RequestAborted);
            // The hard cap as well: a lease that ended just before the line above never cancels its token.
            ending.CancelAfter(Clamp(allowed.LeaseExpiresAt - DateTimeOffset.UtcNow));
            var moved = await WebSocketRelay.RunAsync(local, node, ending.Token);
            allowed.Closed(leaseEnding.IsCancellationRequested || allowed.LeaseExpiresAt <= DateTimeOffset.UtcNow ? "lease-ended" : "closed", moved.Up, moved.Down);
        }

        static TimeSpan Clamp(TimeSpan left) => left < TimeSpan.Zero ? TimeSpan.Zero : left;
    }

    static string? Observed(HttpContext context) =>
        context.Request.Headers[ForwarderHeaders.ObservedProcess].FirstOrDefault() is { Length: > 0 } observed ? observed : null;

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
