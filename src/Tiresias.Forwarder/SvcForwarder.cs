using System.Net.WebSockets;
using System.Text;
using Tiresias.Transport;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace Tiresias.Forwarder;

/// <summary>The <c>Forwarder</c> configuration section.</summary>
public sealed class ForwarderOptions
{
    /// <summary>The broker over NetBird, e.g. <c>http://broker.example.internal:7780</c>.</summary>
    public Uri? BrokerUrl { get; set; }
}

/// <summary>
/// <c>* /svc/**</c>, <c>* /raven/**</c>, <c>POST /sql/**</c>: passes the request to the same route on
/// the broker verbatim (raw target, method, body, headers including the <c>tirph_</c> Authorization)
/// and the broker's answer back. All it adds is <see cref="ForwarderHeaders.ObservedProcess"/> and
/// <see cref="ForwarderHeaders.PublicBase"/>; a client-sent <c>X-Tiresias-*</c>
/// header is dropped so a client can't speak for the forwarder. It decides nothing and holds no
/// secret: policy, placeholders and credentials are the broker's. A WebSocket request (RavenDB's
/// Changes API) becomes a WebSocket to the broker, relayed message by message.
/// </summary>
sealed class SvcForwarder(IHttpClientFactory clients, IHttpMessageHandlerFactory handlers, IClientProcessLookup processes, IOptions<ForwarderOptions> options)
{
    public const string ClientName = "broker";

    static readonly HashSet<string> Stripped = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
        "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Host",
    };

    static readonly string[] PlaceholderRoutes = ["/svc/", "/raven/", "/sql/"];

    readonly Uri broker = options.Value.BrokerUrl ?? throw new InvalidOperationException("Forwarder:BrokerUrl is not configured.");

    public async Task HandleAsync(HttpContext context)
    {
        var request = context.Request;
        var ct = context.RequestAborted;
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } raw
            ? raw
            : request.PathBase + request.Path + request.QueryString;
        if (!PlaceholderRoutes.Any(r => rawTarget.StartsWith(r, StringComparison.Ordinal)))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (context.WebSockets.IsWebSocketRequest)
        {
            await RelayWebSocketAsync(context, rawTarget);
            return;
        }

        var target = new Uri(broker.AbsoluteUri.TrimEnd('/') + rawTarget,
            new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true });
        using var message = new HttpRequestMessage(new HttpMethod(request.Method), target);
        if (request.ContentLength > 0 || request.Headers.TransferEncoding.Count > 0)
            message.Content = new StreamContent(request.Body);

        var connectionTokens = request.Headers.Connection.SelectMany(v => (v ?? "").Split(',', StringSplitOptions.TrimEntries)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, values) in request.Headers)
        {
            if (Stripped.Contains(name) || connectionTokens.Contains(name) || name.StartsWith("X-Tiresias-", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!message.Headers.TryAddWithoutValidation(name, values.ToArray()))
                message.Content?.Headers.TryAddWithoutValidation(name, values.ToArray());
        }
        if (processes.Describe(context.Connection) is { } observed)
            message.Headers.TryAddWithoutValidation(ForwarderHeaders.ObservedProcess, HeaderSafe(observed));
        message.Headers.TryAddWithoutValidation(ForwarderHeaders.PublicBase, $"{request.Scheme}://{request.Host}");

        HttpResponseMessage response;
        try
        {
            response = await clients.CreateClient(ClientName).SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (HttpRequestException)
        {
            await Results.Json(new { reason = "broker-unreachable" }, statusCode: StatusCodes.Status502BadGateway).ExecuteAsync(context);
            return;
        }

        using (response)
        {
            context.Response.StatusCode = (int)response.StatusCode;
            foreach (var (name, values) in response.Headers.Concat(response.Content.Headers))
                if (!Stripped.Contains(name))
                    context.Response.Headers[name] = values.ToArray();
            await response.Content.CopyToAsync(context.Response.Body, ct);
        }
    }

    async Task RelayWebSocketAsync(HttpContext context, string rawTarget)
    {
        var target = new Uri((broker.Scheme == Uri.UriSchemeHttps ? "wss" : "ws") + broker.AbsoluteUri[broker.Scheme.Length..].TrimEnd('/') + rawTarget,
            new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true });
        using var upstream = new ClientWebSocket();
        upstream.Options.CollectHttpResponseDetails = true;
        if (context.Request.Headers.Authorization is { Count: > 0 } authorization)
            upstream.Options.SetRequestHeader("Authorization", authorization.ToString());
        if (processes.Describe(context.Connection) is { } observed)
            upstream.Options.SetRequestHeader(ForwarderHeaders.ObservedProcess, HeaderSafe(observed));
        foreach (var protocol in context.WebSockets.WebSocketRequestedProtocols)
            upstream.Options.AddSubProtocol(protocol);
        try
        {
            // The broker client's handler, not an HttpClient: a client would try to buffer the upgraded stream.
            using var invoker = new HttpMessageInvoker(handlers.CreateHandler(ClientName), disposeHandler: false);
            await upstream.ConnectAsync(target, invoker, context.RequestAborted);
        }
        catch (WebSocketException)
        {
            // The broker's refusal keeps its status (its JSON body can't come through an upgrade).
            if (upstream.HttpStatusCode is var status and not 0)
                context.Response.StatusCode = (int)status;
            else
                await Results.Json(new { reason = "broker-unreachable" }, statusCode: StatusCodes.Status502BadGateway).ExecuteAsync(context);
            return;
        }

        using var local = await context.WebSockets.AcceptWebSocketAsync(upstream.SubProtocol);
        await WebSocketRelay.RunAsync(local, upstream, context.RequestAborted);
    }

    /// <summary>Image paths may hold non-ASCII characters, which a header value can't carry.</summary>
    static string HeaderSafe(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(c is >= ' ' and <= '~' ? c : '?');
        return sb.ToString();
    }
}
