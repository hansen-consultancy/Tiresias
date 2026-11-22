using System.Net;
using System.Net.Http.Headers;
using Tiresias.Protocol;

namespace Tiresias.Alerts;

public enum SinkProblem
{
    None,
    /// <summary>Not an absolute URL.</summary>
    NotAbsolute,
    /// <summary>Not HTTPS, and not plain HTTP to loopback.</summary>
    NotHttps,
    /// <summary>A user name or password in the URL.</summary>
    UserInfo,
    /// <summary>Not an RFC 9110 token.</summary>
    HeaderName,
    /// <summary>CR, LF or another control character.</summary>
    HeaderValue,
    /// <summary><c>Host</c>, <c>Content-Length</c>, <c>Content-Type</c> or <c>Idempotency-Key</c>.</summary>
    HeaderReserved,
    HeaderTwice,
    /// <summary>A sink id that isn't 1 to 32 of a-z, 0-9 and <c>-</c>.</summary>
    Id,
    /// <summary>An ntfy server URL with a query or fragment, or a topic URL whose last segment isn't 1 to 64 of A-Z, a-z, 0-9, <c>-</c> and <c>_</c>.</summary>
    Topic,
    /// <summary>An ntfy token that isn't 1 to 256 visible ASCII characters.</summary>
    Token,
}

/// <summary>What a sink definition may hold (docs/alerts.md, <i>Sinks</i>): checked by the form and again before every send.</summary>
public static class SinkRules
{
    /// <summary>Set by the transport itself; a user header could otherwise smuggle a second body or retarget the request.</summary>
    public static readonly IReadOnlySet<string> Reserved =
        new HashSet<string>(["Host", "Content-Length", "Content-Type", "Idempotency-Key"], StringComparer.OrdinalIgnoreCase);

    public static SinkProblem CheckId(string id) =>
        id.Length is >= 1 and <= 32 && id.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-') ? SinkProblem.None : SinkProblem.Id;

    /// <summary>HTTPS, or plain HTTP to loopback for a local relay; never a user name or password in it.</summary>
    public static SinkProblem CheckUrl(string text, out Uri? url)
    {
        if (!Uri.TryCreate(text.Trim(), UriKind.Absolute, out url) || url.IsFile || url.IsUnc)
            return SinkProblem.NotAbsolute;
        if (url.UserInfo.Length > 0)
            return SinkProblem.UserInfo;
        return url.Scheme == Uri.UriSchemeHttps || (url.Scheme == Uri.UriSchemeHttp && url.IsLoopback) ? SinkProblem.None : SinkProblem.NotHttps;
    }

    public static SinkProblem CheckHeader(string name, string value)
    {
        if (name.Length == 0 || !name.All(IsTokenChar))
            return SinkProblem.HeaderName;
        if (Reserved.Contains(name))
            return SinkProblem.HeaderReserved;
        return value.Any(c => char.IsControl(c) && c != '\t') ? SinkProblem.HeaderValue : SinkProblem.None;
    }

    /// <summary>
    /// The topic URL for <paramref name="topic"/> on the ntfy <paramref name="server"/>: HTTPS (or HTTP
    /// to loopback), no query or fragment, a topic ntfy accepts. A server may sit under a path.
    /// </summary>
    public static SinkProblem CheckNtfy(string server, string topic, out Uri? url)
    {
        url = null;
        if (CheckUrl(server, out var parsed) is var problem and not SinkProblem.None)
            return problem;
        if (parsed!.Query.Length > 0 || parsed.Fragment.Length > 0 || !IsTopic(topic.Trim()))
            return SinkProblem.Topic;
        url = new Uri(parsed.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/" + topic.Trim(), UriKind.Absolute);
        return SinkProblem.None;
    }

    /// <summary>1 to 256 visible ASCII characters: it goes in a header after <c>Bearer</c>.</summary>
    public static SinkProblem CheckToken(string token) =>
        token.Length is >= 1 and <= 256 && token.All(c => c is > ' ' and < (char)0x7F) ? SinkProblem.None : SinkProblem.Token;

    public static SinkProblem Check(AlertSink sink) => sink switch
    {
        WebhookSink webhook => Check(webhook),
        NtfySink ntfy => Check(ntfy),
        LcdHubSink hub => CheckId(hub.Id),
        _ => throw new ArgumentOutOfRangeException(nameof(sink), sink.Kind, "Not a sink kind this build knows."),
    };

    static SinkProblem Check(NtfySink sink)
    {
        var problem = CheckId(sink.Id);
        if (problem == SinkProblem.None)
            problem = CheckUrl(sink.Topic.OriginalString, out _);
        if (problem == SinkProblem.None && (sink.Topic.Query.Length > 0 || sink.Topic.Fragment.Length > 0 || !IsTopic(sink.Topic.Segments[^1])))
            problem = SinkProblem.Topic;
        if (problem == SinkProblem.None && sink.Token is not null)
            problem = CheckToken(sink.Token);
        return problem;
    }

    static SinkProblem Check(WebhookSink sink)
    {
        var problem = CheckId(sink.Id);
        if (problem == SinkProblem.None)
            problem = CheckUrl(sink.Url.OriginalString, out _);
        foreach (var (name, value) in sink.Headers)
            if (problem == SinkProblem.None)
                problem = CheckHeader(name, value);
        if (problem == SinkProblem.None && sink.Headers.Select(h => h.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != sink.Headers.Count)
            problem = SinkProblem.HeaderTwice;
        return problem;
    }

    /// <summary>What ntfy accepts as a topic name.</summary>
    static bool IsTopic(string name) => name.Length is >= 1 and <= 64 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>RFC 9110 <c>tchar</c>.</summary>
    static bool IsTokenChar(char c) => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal);
}

public enum DeliveryStatus
{
    Delivered,
    /// <summary>Try again later: no answer, a 5xx, a 429.</summary>
    Retry,
    /// <summary>The definition is wrong (a 4xx, a redirect, an invalid header): retrying would only repeat the refusal.</summary>
    Stop,
}

/// <summary>
/// How one attempt went. Holds only what may be logged: the status code and the exception's type,
/// never its message (it can quote the URL), a header or the body.
/// </summary>
public sealed record DeliveryResult(DeliveryStatus Status, int? StatusCode = null, TimeSpan? RetryAfter = null, string? Error = null)
{
    public override string ToString() =>
        $"{Status}{(StatusCode is { } code ? $" {code}" : "")}{(Error is { } error ? $" {error}" : "")}";
}

/// <summary>
/// Posts an <see cref="AlertPayload"/> to a sink over HTTP (docs/alerts.md, <i>Sinks</i>): to a webhook
/// as <c>tiresias.alert/v1</c> JSON with the sink's headers, to ntfy as <see cref="NtfyFormat"/> says.
/// Every request carries <c>Idempotency-Key</c> set to the payload's id, follows no redirect (so a
/// credential never reaches another host), gives up after 10 seconds and uses the system proxy.
/// </summary>
public sealed class HttpAlertTransport : IDisposable
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    readonly HttpClient client;
    readonly TimeProvider time;

    public HttpAlertTransport() : this(CreateHandler(), TimeProvider.System)
    {
    }

    /// <param name="handler">The innermost handler; tests pass a fake.</param>
    public HttpAlertTransport(HttpMessageHandler handler, TimeProvider time)
    {
        client = new HttpClient(handler, disposeHandler: true) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
        this.time = time;
    }

    /// <summary>Redirects off, the system proxy, no cookies and no default credentials.</summary>
    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseProxy = true,
        UseCookies = false,
        Credentials = null,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    };

    public async Task<DeliveryResult> DeliverAsync(AlertPayload payload, AlertSink sink, CancellationToken ct)
    {
        if (SinkRules.Check(sink) is var problem and not SinkProblem.None)
            return new(DeliveryStatus.Stop, Error: problem.ToString());

        using var request = sink switch
        {
            WebhookSink webhook => WebhookRequest(payload, webhook),
            NtfySink ntfy => NtfyFormat.Request(payload, ntfy),
            _ => throw new ArgumentOutOfRangeException(nameof(sink), sink.Kind, "Not a sink kind this build knows."),
        };
        request.Headers.TryAddWithoutValidation("Idempotency-Key", payload.Id);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            return Classify((int)response.StatusCode, RetryAfter(response.Headers.RetryAfter, time.GetUtcNow()));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(DeliveryStatus.Retry, Error: "Timeout");
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return new(DeliveryStatus.Retry, Error: e.GetType().Name);
        }
    }

    static HttpRequestMessage WebhookRequest(AlertPayload payload, WebhookSink sink)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, sink.Url) { Content = new ByteArrayContent(AlertWire.Serialize(payload)) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        foreach (var (name, value) in sink.Headers)
            if (!request.Headers.TryAddWithoutValidation(name, value))
                request.Content.Headers.TryAddWithoutValidation(name, value);
        return request;
    }

    /// <summary>2xx delivered; 429 and 503 retry after <c>Retry-After</c>; any other 4xx, and a redirect, stop the sink; the rest retry.</summary>
    internal static DeliveryResult Classify(int code, TimeSpan? retryAfter) => code switch
    {
        >= 200 and < 300 => new(DeliveryStatus.Delivered, code),
        (int)HttpStatusCode.TooManyRequests or (int)HttpStatusCode.ServiceUnavailable => new(DeliveryStatus.Retry, code, retryAfter),
        >= 300 and < 500 => new(DeliveryStatus.Stop, code),
        _ => new(DeliveryStatus.Retry, code),
    };

    static TimeSpan? RetryAfter(RetryConditionHeaderValue? header, DateTimeOffset now) => header switch
    {
        { Delta: { } delta } => delta,
        { Date: { } date } => date > now ? date - now : TimeSpan.Zero,
        _ => null,
    };

    public void Dispose() => client.Dispose();
}
