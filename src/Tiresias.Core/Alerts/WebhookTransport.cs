using System.Net;
using System.Net.Http.Headers;
using Tiresias.Protocol;

namespace Tiresias.Alerts;

public enum WebhookProblem
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
}

/// <summary>What a webhook definition may hold (docs/alerts.md, <i>Sinks</i>): checked by the form and again before every send.</summary>
public static class WebhookRules
{
    /// <summary>Set by the transport itself; a user header could otherwise smuggle a second body or retarget the request.</summary>
    public static readonly IReadOnlySet<string> Reserved =
        new HashSet<string>(["Host", "Content-Length", "Content-Type", "Idempotency-Key"], StringComparer.OrdinalIgnoreCase);

    public static WebhookProblem CheckId(string id) =>
        id.Length is >= 1 and <= 32 && id.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-') ? WebhookProblem.None : WebhookProblem.Id;

    /// <summary>HTTPS, or plain HTTP to loopback for a local relay; never a user name or password in it.</summary>
    public static WebhookProblem CheckUrl(string text, out Uri? url)
    {
        if (!Uri.TryCreate(text.Trim(), UriKind.Absolute, out url) || url.IsFile || url.IsUnc)
            return WebhookProblem.NotAbsolute;
        if (url.UserInfo.Length > 0)
            return WebhookProblem.UserInfo;
        return url.Scheme == Uri.UriSchemeHttps || (url.Scheme == Uri.UriSchemeHttp && url.IsLoopback) ? WebhookProblem.None : WebhookProblem.NotHttps;
    }

    public static WebhookProblem CheckHeader(string name, string value)
    {
        if (name.Length == 0 || !name.All(IsTokenChar))
            return WebhookProblem.HeaderName;
        if (Reserved.Contains(name))
            return WebhookProblem.HeaderReserved;
        return value.Any(c => char.IsControl(c) && c != '\t') ? WebhookProblem.HeaderValue : WebhookProblem.None;
    }

    public static WebhookProblem Check(WebhookSink sink)
    {
        var problem = CheckId(sink.Id);
        if (problem == WebhookProblem.None)
            problem = CheckUrl(sink.Url.OriginalString, out _);
        foreach (var (name, value) in sink.Headers)
            if (problem == WebhookProblem.None)
                problem = CheckHeader(name, value);
        if (problem == WebhookProblem.None && sink.Headers.Select(h => h.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != sink.Headers.Count)
            problem = WebhookProblem.HeaderTwice;
        return problem;
    }

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
/// Posts a <see cref="AlertPayload"/> to a webhook as <c>tiresias.alert/v1</c> JSON
/// (docs/alerts.md, <i>Sinks</i>): the sink's headers, <c>Idempotency-Key</c> set to the payload's id,
/// no redirects followed (so the headers never reach another host), 10 seconds, the system proxy.
/// </summary>
public sealed class WebhookTransport : IDisposable
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    readonly HttpClient client;
    readonly TimeProvider time;

    public WebhookTransport() : this(CreateHandler(), TimeProvider.System)
    {
    }

    /// <param name="handler">The innermost handler; tests pass a fake.</param>
    public WebhookTransport(HttpMessageHandler handler, TimeProvider time)
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

    public async Task<DeliveryResult> DeliverAsync(AlertPayload payload, WebhookSink sink, CancellationToken ct)
    {
        if (WebhookRules.Check(sink) is var problem and not WebhookProblem.None)
            return new(DeliveryStatus.Stop, Error: problem.ToString());

        using var request = new HttpRequestMessage(HttpMethod.Post, sink.Url) { Content = new ByteArrayContent(AlertWire.Serialize(payload)) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("Idempotency-Key", payload.Id);
        foreach (var (name, value) in sink.Headers)
            if (!request.Headers.TryAddWithoutValidation(name, value))
                request.Content.Headers.TryAddWithoutValidation(name, value);

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
