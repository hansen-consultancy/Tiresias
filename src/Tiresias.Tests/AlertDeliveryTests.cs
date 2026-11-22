using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using NSec.Cryptography;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Decoys;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Tests;

/// <summary>A clock whose timers fire only when the test moves it, so backoff waits take no real time.</summary>
sealed class SteppedTime(DateTimeOffset start) : TimeProvider
{
    readonly Lock gate = new();
    readonly List<SteppedTimer> timers = [];
    DateTimeOffset now = start;

    public override DateTimeOffset GetUtcNow()
    {
        lock (gate)
            return now;
    }

    /// <summary>Timers waiting to fire: a worker that has gone to sleep has one.</summary>
    public int Pending
    {
        get
        {
            lock (gate)
                return timers.Count;
        }
    }

    public void Advance(TimeSpan by)
    {
        List<SteppedTimer> due;
        lock (gate)
        {
            now += by;
            due = [.. timers.Where(t => t.Due <= now)];
        }
        foreach (var timer in due)
            timer.Fire();
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new SteppedTimer(this, callback, state);
        timer.Change(dueTime, period);
        return timer;
    }

    sealed class SteppedTimer(SteppedTime time, TimerCallback callback, object? state) : ITimer
    {
        public DateTimeOffset Due;
        TimeSpan period;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (time.gate)
            {
                time.timers.Remove(this);
                this.period = period;
                if (dueTime == Timeout.InfiniteTimeSpan)
                    return true;
                Due = time.now + dueTime;
                time.timers.Add(this);
            }
            if (dueTime == TimeSpan.Zero)
                Fire();
            return true;
        }

        public void Fire()
        {
            lock (time.gate)
            {
                time.timers.Remove(this);
                if (period > TimeSpan.Zero && period != Timeout.InfiniteTimeSpan)
                {
                    Due += period;
                    time.timers.Add(this);
                }
            }
            callback(state);
        }

        public void Dispose()
        {
            lock (time.gate)
                time.timers.Remove(this);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>Answers each request with what the test says, keeping every request's headers and body as sent.</summary>
sealed class FakeHandler(Func<HttpRequestMessage, int, HttpResponseMessage> respond) : HttpMessageHandler
{
    public sealed record Captured(Uri Url, IReadOnlyList<KeyValuePair<string, string>> Headers, byte[] Body)
    {
        public string Header(string name) => Headers.Single(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

        /// <summary>Headers and body as bytes on the wire would carry them, for canary checks.</summary>
        public string Wire => string.Concat(Headers.Select(h => $"{h.Key}: {h.Value}\n")) + "\n" + Encoding.UTF8.GetString(Body);
    }

    public readonly ConcurrentQueue<Captured> Requests = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var headers = request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
            .Select(h => KeyValuePair.Create(h.Key, string.Join(", ", h.Value))).ToList();
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(ct);
        Requests.Enqueue(new(request.RequestUri!, headers, body));
        return respond(request, Requests.Count);
    }

    public static FakeHandler Always(HttpStatusCode code) => new((_, _) => new HttpResponseMessage(code));
}

public class SinkRulesTests
{
    [TestCase("https://hooks.example.com/t", SinkProblem.None)]
    [TestCase("http://localhost:8080/relay", SinkProblem.None)]
    [TestCase("http://127.0.0.1/relay", SinkProblem.None)]
    [TestCase("http://[::1]/relay", SinkProblem.None)]
    [TestCase("http://hooks.example.com/t", SinkProblem.NotHttps)]
    [TestCase("ftp://hooks.example.com/t", SinkProblem.NotHttps)]
    [TestCase("https://alice:pw@hooks.example.com/t", SinkProblem.UserInfo)]
    [TestCase("hooks.example.com/t", SinkProblem.NotAbsolute)]
    [TestCase("C:\\temp\\x", SinkProblem.NotAbsolute)]
    public void Urls(string url, SinkProblem expected) =>
        Assert.That(SinkRules.CheckUrl(url, out _), Is.EqualTo(expected));

    [TestCase("Authorization", "Bearer abc", SinkProblem.None)]
    [TestCase("X-Api-Key", "k\tv", SinkProblem.None)]
    [TestCase("X Api", "v", SinkProblem.HeaderName)]
    [TestCase("X-Api:", "v", SinkProblem.HeaderName)]
    [TestCase("", "v", SinkProblem.HeaderName)]
    [TestCase("X-Api", "v\r\nX-Evil: 1", SinkProblem.HeaderValue)]
    [TestCase("X-Api", "v\n", SinkProblem.HeaderValue)]
    [TestCase("host", "evil.example.com", SinkProblem.HeaderReserved)]
    [TestCase("Content-Length", "1", SinkProblem.HeaderReserved)]
    [TestCase("Content-Type", "text/plain", SinkProblem.HeaderReserved)]
    [TestCase("Idempotency-Key", "x", SinkProblem.HeaderReserved)]
    public void Headers(string name, string value, SinkProblem expected) =>
        Assert.That(SinkRules.CheckHeader(name, value), Is.EqualTo(expected));

    [Test]
    public void The_same_header_twice_is_refused() =>
        Assert.That(SinkRules.Check(new WebhookSink("siem", new("https://hooks.example.com"), [new("X-A", "1"), new("x-a", "2")])), Is.EqualTo(SinkProblem.HeaderTwice));
}

public class HttpAlertTransportTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);

    static readonly AlertPayload Payload = new("01JD2K8Q4X9V7M3N5P6R8S0T2W", "decoy.used", AlertSeverity.Critical, "Decoy credential used",
        "workstation", T0, 1, "decoy.used:5e1f0c9a2b7d4e86", null);

    static readonly WebhookSink Sink = new("siem", new("https://hooks.example.com/t?key=CANARY-url-secret"), [new("Authorization", "Bearer CANARY-header-secret")]);

    static async Task<(DeliveryResult Result, FakeHandler Handler)> Deliver(FakeHandler handler, WebhookSink? sink = null)
    {
        using var transport = new HttpAlertTransport(handler, new SteppedTime(T0));
        return (await transport.DeliverAsync(Payload, sink ?? Sink, CancellationToken.None), handler);
    }

    [Test]
    public async Task Posts_the_payload_with_its_id_as_the_idempotency_key_and_the_sinks_headers()
    {
        var (result, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.Accepted));

        var sent = handler.Requests.Single();
        Assert.That(result.Status, Is.EqualTo(DeliveryStatus.Delivered));
        Assert.That(sent.Url, Is.EqualTo(Sink.Url));
        Assert.That(sent.Body, Is.EqualTo(AlertWire.Serialize(Payload)));
        Assert.That(sent.Header("Idempotency-Key"), Is.EqualTo(Payload.Id));
        Assert.That(sent.Header("Content-Type"), Does.StartWith("application/json"));
        Assert.That(sent.Header("Authorization"), Is.EqualTo("Bearer CANARY-header-secret"));
    }

    [Test]
    public async Task Credentials_travel_only_in_the_request_headers()
    {
        var (_, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK));

        var sent = handler.Requests.Single();
        Assert.That(Encoding.UTF8.GetString(sent.Body), Does.Not.Contain("CANARY"));
        Assert.That(sent.Headers.Where(h => h.Key != "Authorization").Select(h => h.Value), Has.None.Contains("CANARY"));
    }

    [Test]
    public void The_real_handler_follows_no_redirect_and_uses_the_system_proxy()
    {
        using var handler = HttpAlertTransport.CreateHandler();
        Assert.That(handler.AllowAutoRedirect, Is.False);
        Assert.That(handler.UseProxy, Is.True);
        Assert.That(handler.Proxy, Is.Null, "null means the system proxy");
        Assert.That(handler.UseCookies, Is.False);
    }

    [Test]
    public async Task A_redirect_is_not_followed_and_stops_the_sink()
    {
        var (result, handler) = await Deliver(new((_, _) =>
            new HttpResponseMessage(HttpStatusCode.Found) { Headers = { Location = new("https://evil.example.com/") } }));

        Assert.That(handler.Requests, Has.Count.EqualTo(1));
        Assert.That(result.Status, Is.EqualTo(DeliveryStatus.Stop));
        Assert.That(result.StatusCode, Is.EqualTo(302));
    }

    [TestCase(HttpStatusCode.BadRequest, DeliveryStatus.Stop)]
    [TestCase(HttpStatusCode.Unauthorized, DeliveryStatus.Stop)]
    [TestCase(HttpStatusCode.NotFound, DeliveryStatus.Stop)]
    [TestCase(HttpStatusCode.TooManyRequests, DeliveryStatus.Retry)]
    [TestCase(HttpStatusCode.InternalServerError, DeliveryStatus.Retry)]
    [TestCase(HttpStatusCode.ServiceUnavailable, DeliveryStatus.Retry)]
    [TestCase(HttpStatusCode.NoContent, DeliveryStatus.Delivered)]
    public async Task Classifies_the_answer(HttpStatusCode code, DeliveryStatus expected) =>
        Assert.That((await Deliver(FakeHandler.Always(code))).Result.Status, Is.EqualTo(expected));

    [Test]
    public async Task Retry_after_as_seconds_and_as_a_date_is_honoured()
    {
        var (seconds, _) = await Deliver(new((_, _) =>
            new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Headers = { RetryAfter = new(TimeSpan.FromSeconds(120)) } }));
        var (date, _) = await Deliver(new((_, _) =>
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Headers = { RetryAfter = new(T0.AddMinutes(5)) } }));

        Assert.That(seconds.RetryAfter, Is.EqualTo(TimeSpan.FromSeconds(120)));
        Assert.That(date.RetryAfter, Is.EqualTo(TimeSpan.FromMinutes(5)));
    }

    [Test]
    public async Task A_failure_reports_the_exception_type_only()
    {
        var (result, _) = await Deliver(new((request, _) => throw new HttpRequestException($"No such host: {request.RequestUri} Bearer CANARY-header-secret")));

        Assert.That(result.Status, Is.EqualTo(DeliveryStatus.Retry));
        Assert.That(result.Error, Is.EqualTo(nameof(HttpRequestException)));
        Assert.That(result.ToString(), Does.Not.Contain("CANARY").And.Not.Contain("example.com"));
    }

    [Test]
    public async Task An_invalid_definition_is_never_sent()
    {
        var (result, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK),
            Sink with { Headers = [new("X-A", "v\r\nHost: evil.example.com")] });

        Assert.That(handler.Requests, Is.Empty);
        Assert.That(result.Status, Is.EqualTo(DeliveryStatus.Stop));
    }

    [Test]
    public async Task A_plain_http_url_off_loopback_is_never_sent()
    {
        var (result, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK), Sink with { Url = new("http://hooks.example.com/t") });

        Assert.That(handler.Requests, Is.Empty);
        Assert.That(result.Status, Is.EqualTo(DeliveryStatus.Stop));
    }

    [Test]
    public void A_sink_prints_as_its_id_only() =>
        Assert.That($"{Sink} {new AlertsConfig("workstation", new byte[32], [Sink])}", Does.Not.Contain("CANARY").And.Not.Contain("example.com"));
}

public class AlertDeliveryTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);

    [Test]
    public void Backoff_doubles_from_30_seconds_up_to_30_minutes()
    {
        var waits = Enumerable.Range(1, 9).Select(DeliveryPolicy.Backoff).Select(t => t.TotalSeconds);
        Assert.That(waits, Is.EqualTo(new double[] { 30, 60, 120, 240, 480, 960, 1800, 1800, 1800 }));
    }

    [Test]
    public void Retry_after_waits_at_least_as_long_as_the_receiver_asks_and_the_backoff()
    {
        Assert.That(DeliveryPolicy.NextAttempt(new(DeliveryStatus.Retry, 429, TimeSpan.FromMinutes(10)), 1, T0), Is.EqualTo(T0.AddMinutes(10)));
        Assert.That(DeliveryPolicy.NextAttempt(new(DeliveryStatus.Retry, 429, TimeSpan.Zero), 3, T0), Is.EqualTo(T0.AddMinutes(2)));
        Assert.That(DeliveryPolicy.NextAttempt(new(DeliveryStatus.Retry, 429, TimeSpan.FromSeconds(3_000_000)), 1, T0), Is.EqualTo(T0.AddHours(24)));
    }

    [Test]
    public async Task A_huge_retry_after_holds_its_sink_and_the_others_still_go()
    {
        var time = new SteppedTime(T0);
        var handler = new FakeHandler((request, _) => request.RequestUri!.AbsolutePath == "/a"
            ? new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Headers = { RetryAfter = new(TimeSpan.FromSeconds(3_000_000)) } }
            : new HttpResponseMessage(HttpStatusCode.OK));
        await using var sender = new AlertSender(new HttpAlertTransport(handler, time), time, _ => { });
        sender.Configure([Sink with { Id = "a", Url = new("https://hooks.example.com/a") }, Sink with { Id = "b", Url = new("https://hooks.example.com/b") }]);
        sender.Start();
        sender.Enqueue(new("a", Payload(1)));
        await Until(() => handler.Requests.Count == 1 && time.Pending == 1);

        sender.Enqueue(new("b", Payload(2)));
        await Until(() => handler.Requests.Count == 2);
        Assert.That(handler.Requests.Last().Url.AbsolutePath, Is.EqualTo("/b"));
    }

    [Test]
    public void An_alert_is_given_up_after_24_hours()
    {
        Assert.That(DeliveryPolicy.Expired(T0, T0.AddHours(24).AddTicks(-1)), Is.False);
        Assert.That(DeliveryPolicy.Expired(T0, T0.AddHours(24)), Is.True);
    }

    static AlertPayload Payload(int n) => new($"ID{n:D24}", "decoy.used", AlertSeverity.Critical, "Decoy credential used", "workstation", T0, 1, "k", null);

    static readonly WebhookSink Sink = new("siem", new("https://hooks.example.com/t?key=CANARY-url-secret"), [new("Authorization", "Bearer CANARY-header-secret")]);

    static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
            await Task.Delay(10);
        Assert.That(condition(), Is.True, "timed out");
    }

    [Test]
    public async Task Retries_with_backoff_then_delivers_in_order()
    {
        var time = new SteppedTime(T0);
        var handler = new FakeHandler((_, n) => new HttpResponseMessage(n == 1 ? HttpStatusCode.InternalServerError : HttpStatusCode.OK));
        var log = new ConcurrentQueue<string>();
        await using var sender = new AlertSender(new HttpAlertTransport(handler, time), time, log.Enqueue);
        sender.Configure([Sink]);
        sender.Start();
        sender.Enqueue(new("siem", Payload(1)));
        sender.Enqueue(new("siem", Payload(2)));

        await Until(() => handler.Requests.Count == 1 && sender.Waiting("siem") == 2 && time.Pending == 1);
        time.Advance(TimeSpan.FromSeconds(29));
        await Task.Delay(50);
        Assert.That(handler.Requests, Has.Count.EqualTo(1), "nothing before the backoff ends");
        time.Advance(TimeSpan.FromSeconds(1));
        await Until(() => handler.Requests.Count == 3);

        Assert.That(handler.Requests.Select(r => r.Header("Idempotency-Key")), Is.EqualTo(new[] { Payload(1).Id, Payload(1).Id, Payload(2).Id }));
        Assert.That(log, Has.Some.Contains("sink siem failed: Retry 500"));
    }

    [Test]
    public async Task A_4xx_stops_the_sink_until_its_target_changes()
    {
        var time = new SteppedTime(T0);
        var handler = new FakeHandler((request, _) => new HttpResponseMessage(
            request.RequestUri!.Host == "hooks.example.com" ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
        var log = new ConcurrentQueue<string>();
        await using var sender = new AlertSender(new HttpAlertTransport(handler, time), time, log.Enqueue);
        sender.Configure([Sink]);
        sender.Start();
        sender.Enqueue(new("siem", Payload(1)));
        sender.Enqueue(new("siem", Payload(2)));

        await Until(() => sender.IsStopped("siem"));
        time.Advance(TimeSpan.FromHours(1));
        await Task.Delay(50);
        Assert.That(handler.Requests, Has.Count.EqualTo(1));

        sender.Configure([Sink with { Url = new("https://fixed.example.com/t") }]);
        await Until(() => handler.Requests.Count == 3);
        Assert.That(sender.IsStopped("siem"), Is.False);
        Assert.That(log, Has.Some.Contains("sink siem stopped: Stop 401"));
    }

    [Test]
    public async Task An_alert_undelivered_for_24_hours_is_dropped()
    {
        var time = new SteppedTime(T0);
        var handler = FakeHandler.Always(HttpStatusCode.BadGateway);
        var log = new ConcurrentQueue<string>();
        await using var sender = new AlertSender(new HttpAlertTransport(handler, time), time, log.Enqueue);
        sender.Configure([Sink]);
        sender.Start();
        sender.Enqueue(new("siem", Payload(1)));
        await Until(() => handler.Requests.Count == 1);

        for (var i = 0; i < 60 && sender.Waiting("siem") > 0; i++)
        {
            await Until(() => time.Pending == 1 || sender.Waiting("siem") == 0);
            time.Advance(TimeSpan.FromMinutes(30));
        }
        await Until(() => sender.Waiting("siem") == 0);
        Assert.That(log, Has.Some.Contains("dropped decoy.used after 24 hours"));
    }

    [Test]
    public async Task Logs_and_errors_never_carry_the_url_a_header_or_the_body()
    {
        var time = new SteppedTime(T0);
        var handler = new FakeHandler((request, n) => n == 1
            ? throw new HttpRequestException($"Failed {request.RequestUri} {request.Headers.Authorization}")
            : new HttpResponseMessage(HttpStatusCode.Forbidden));
        var log = new ConcurrentQueue<string>();
        await using var sender = new AlertSender(new HttpAlertTransport(handler, time), time, log.Enqueue);
        sender.Configure([Sink]);
        sender.Start();
        sender.Enqueue(new("siem", Payload(1) with { Title = "CANARY-body" }));
        await Until(() => handler.Requests.Count == 1 && log.Count == 1 && time.Pending == 1);
        time.Advance(TimeSpan.FromSeconds(30));
        await Until(() => sender.IsStopped("siem"));

        Assert.That(log, Has.Count.EqualTo(2));
        Assert.That(log, Has.All.Not.Contains("CANARY").And.All.Not.Contains("example.com").And.All.Not.Contains("Bearer"));
        Assert.That(log, Has.Some.Contains("HttpRequestException"));
    }
}

public class AlertCenterTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    const string HeaderSecret = "CANARY-header-secret";
    const string UrlSecret = "CANARY-url-secret";

    static WebhookSink Sink(string id, AlertRedaction redaction) =>
        new(id, new($"https://hooks.example.com/{id}?key={UrlSecret}"), [new("Authorization", $"Bearer {HeaderSecret}")], AlertSeverity.High, redaction);

    static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
            await Task.Delay(10);
        Assert.That(condition(), Is.True, "timed out");
    }

    [Test]
    public async Task Events_before_the_first_unlock_wait_and_go_after_it()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Start();
        center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));
        await Task.Delay(50);
        Assert.That(handler.Requests, Is.Empty);

        center.Use(new("workstation", InstallKey, [Sink("siem", AlertRedaction.Public)]), null);
        await Until(() => handler.Requests.Count == 1);
        Assert.That(AlertWire.Parse(handler.Requests.Single().Body).Event, Is.EqualTo("decoy.used"));
    }

    [Test]
    public async Task A_muted_sink_gets_nothing_and_a_removed_one_is_gone()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Start();
        center.Use(new("workstation", InstallKey, [Sink("a", AlertRedaction.Public), Sink("b", AlertRedaction.Public), Sink("c", AlertRedaction.Public)]),
            new Dictionary<string, SinkNarrowing> { ["a"] = new(Muted: true), ["b"] = new(Removed: true) });
        center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));

        await Until(() => handler.Requests.Count == 1);
        await Task.Delay(50);
        Assert.That(handler.Requests.Single().Url.AbsolutePath, Is.EqualTo("/c"));
    }

    [Test]
    public async Task Muting_drops_what_waits_for_the_sink_and_unmuting_replays_none_of_it()
    {
        var handler = new FakeHandler((_, n) => new HttpResponseMessage(n == 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Sender.Start();
        var config = new AlertsConfig("workstation", InstallKey, [Sink("a", AlertRedaction.Public)]);
        center.Use(config, null);
        center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));
        await Until(() => handler.Requests.Count == 1 && time.Pending == 1);

        center.Use(config, new Dictionary<string, SinkNarrowing> { ["a"] = new(Muted: true) });
        time.Advance(TimeSpan.FromHours(1));
        await Task.Delay(50);
        center.Use(config, null);
        time.Advance(TimeSpan.FromHours(1));
        await Task.Delay(50);

        Assert.That(handler.Requests, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task A_test_alert_goes_to_one_sink_every_time_it_is_asked()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Use(new("workstation", InstallKey, [Sink("a", AlertRedaction.Public), Sink("b", AlertRedaction.Trusted)]), null);

        var first = await center.SendTestAsync("b", CancellationToken.None);
        var second = await center.SendTestAsync("b", CancellationToken.None);

        Assert.That(new[] { first!.Status, second!.Status }, Is.All.EqualTo(DeliveryStatus.Delivered));
        Assert.That(handler.Requests.Select(r => r.Url.AbsolutePath), Is.EqualTo(new[] { "/b", "/b" }));
        var payload = AlertWire.Parse(handler.Requests.First().Body);
        Assert.That((payload.Event, payload.Machine, payload.Detail), Is.EqualTo(("alerts.test", "workstation", (TrustedDetail?)null)));
        Assert.That(await center.SendTestAsync("gone", CancellationToken.None), Is.Null);
    }

    // ---- Canary through the first source mapping (decoy.used) and the webhook formatter, as captured bytes. ----

    [TestCase(AlertRedaction.Public)]
    [TestCase(AlertRedaction.Trusted)]
    public async Task No_value_token_or_credential_leaves_and_names_only_in_a_trusted_detail(AlertRedaction redaction)
    {
        // The decoy's value and a placeholder token travel beside the event: in the endpoint the program
        // reached, which the mapping must leave out. Names and paths are what the planner may pass on.
        const string Value = "CANARY-value";
        const string Token = "CANARY-token";
        var hit = new DecoyHit(DecoyUse.AdminToken, $"http://127.0.0.1:5999/admin?token={Value}&placeholder={Token}", 4242,
            "C:\\Users\\alice\\CANARY-1\\x.exe", T0);
        var alert = AlertSources.DecoyUsed(hit, ["CANARY-2.exe (7)", "CANARY-3.exe (8)"], "CANARY-4")!;

        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        var log = new ConcurrentQueue<string>();
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, log.Enqueue);
        center.Start();
        center.Use(new("workstation", InstallKey, [Sink("siem", redaction)]), null);
        center.Raise(alert);
        await Until(() => handler.Requests.Count == 1);

        var sent = handler.Requests.Single();
        var wire = sent.Wire;
        Assert.That(wire, Does.Not.Contain(Value).And.Not.Contain(Token));
        Assert.That(Encoding.UTF8.GetString(sent.Body), Does.Not.Contain(HeaderSecret).And.Not.Contain(UrlSecret));
        Assert.That(Regex.Matches(wire, HeaderSecret).Count, Is.EqualTo(1), "the credential once, in its header");
        Assert.That(log, Has.All.Not.Contains("CANARY"));

        var json = JsonNode.Parse(sent.Body)!.AsObject();
        var detail = json["detail"]?.ToJsonString() ?? "";
        json.Remove("detail");
        Assert.That(json.ToJsonString(), Does.Not.Contain("CANARY").And.Not.Contain("alice").And.Not.Contain("4242"));
        Assert.That(sent.Headers.Where(h => h.Key != "Authorization").Select(h => h.Value), Has.None.Contains("CANARY"));
        if (redaction == AlertRedaction.Public)
            Assert.That(detail, Is.Empty);
        else
            Assert.That(Regex.Matches(detail, "CANARY-\\d").Select(m => m.Value).Distinct(), Is.EquivalentTo(new[] { "CANARY-1", "CANARY-2", "CANARY-3", "CANARY-4" }));
    }

    [Test]
    public void A_decoy_file_read_is_not_decoy_used() =>
        Assert.That(AlertSources.DecoyUsed(new(DecoyUse.Read, "C:\\decoy.txt", 1, "C:\\x.exe", T0), [], "the decoy file"), Is.Null);
}

public class AlertsFileTests
{
    static readonly X25519KeyWrapper Hello = X25519KeyWrapper.ForKey("hello", Key.Create(KeyAgreementAlgorithm.X25519));
    static readonly (X25519KeyWrapper Public, X25519KeyWrapper Private) RecoveryPair = NewRecovery();
    static readonly X25519KeyWrapper RecoveryPublic = RecoveryPair.Public;
    static readonly X25519KeyWrapper Recovery = RecoveryPair.Private;

    /// <summary>The recovery key as the app holds it (the public half, wrap only) and as the paper restores it.</summary>
    static (X25519KeyWrapper, X25519KeyWrapper) NewRecovery()
    {
        var key = Key.Create(KeyAgreementAlgorithm.X25519);
        return (X25519KeyWrapper.ForPublicKey("recovery", key.PublicKey.Export(KeyBlobFormat.RawPublicKey)), X25519KeyWrapper.ForKey("recovery", key));
    }

    static readonly AlertsConfig Config = new("workstation", [.. Enumerable.Range(1, 32).Select(i => (byte)i)],
    [
        new WebhookSink("siem", new("https://hooks.example.com/t?key=CANARY-url-secret"), [new("Authorization", "Bearer CANARY-header-secret")], AlertSeverity.High, AlertRedaction.Trusted),
        new WebhookSink("relay", new("http://localhost:8080/"), [], AlertSeverity.Warning),
    ]);

    static void AssertSame(AlertsConfig? back)
    {
        Assert.That(back, Is.Not.Null);
        Assert.That(back!.Machine, Is.EqualTo(Config.Machine));
        Assert.That(back.InstallKey, Is.EqualTo(Config.InstallKey));
        Assert.That(back.Sinks, Has.Count.EqualTo(2));
        for (var i = 0; i < 2; i++)
        {
            Assert.That(back.Sinks[i].SameTarget(Config.Sinks[i]), Is.True);
            Assert.That((back.Sinks[i].Id, back.Sinks[i].Threshold, back.Sinks[i].Redaction),
                Is.EqualTo((Config.Sinks[i].Id, Config.Sinks[i].Threshold, Config.Sinks[i].Redaction)));
        }
    }

    [Test]
    public void Round_trips_sealed_for_hello_and_the_recovery_key_with_no_credential_in_the_file()
    {
        var text = AlertsFile.Seal(Config, 0, Hello, RecoveryPublic);

        Assert.That(SecretsFile.Classify(text), Is.EqualTo(SecretsFileKind.Sealed));
        Assert.That(text, Does.Not.Contain("CANARY").And.Not.Contain("example.com").And.Not.Contain("workstation"));
        var (back, version) = AlertsFile.Open(text, Hello);
        AssertSame(back);
        Assert.That(version, Is.EqualTo(1));
        AssertSame(AlertsFile.Open(text, Recovery).Config);
        Assert.That(UserSecretsVault.Open(AlertsFile.Id, text, Hello).Document["v"]!.GetValue<int>(), Is.EqualTo(AlertsConfig.Version));
    }

    [Test]
    public void Nothing_set_up_is_no_config()
    {
        Assert.That(AlertsFile.Open(null, Hello), Is.EqualTo(((AlertsConfig?)null, 0)));
        Assert.That(AlertsConfig.FromDocument([]), Is.Null);
    }

    [Test]
    public void A_widening_edit_without_the_hello_wrapper_does_not_open()
    {
        // Anyone can seal for the recovery key's public half; only the app holding Hello can seal for Hello.
        var intruder = X25519KeyWrapper.ForKey("hello", Key.Create(KeyAgreementAlgorithm.X25519));
        var widened = Config.With(new WebhookSink("evil", new("https://evil.example.com/"), [], AlertSeverity.Info, AlertRedaction.Trusted));
        var text = AlertsFile.Seal(widened, 1, intruder, RecoveryPublic);

        Assert.Throws<InvalidDataException>(() => AlertsFile.Open(text, Hello));
    }

    [Test]
    public void A_plain_file_or_plain_keys_beside_the_seal_are_refused_not_merged()
    {
        var plain = Config.ToDocument().ToJsonString();
        Assert.Throws<InvalidDataException>(() => AlertsFile.Open(plain, Hello));

        var text = AlertsFile.Seal(Config, 0, Hello, RecoveryPublic);
        var edited = JsonNode.Parse(text)!.AsObject();
        edited["sinks"] = new JsonArray(new JsonObject { ["id"] = "evil", ["kind"] = "webhook", ["url"] = "https://evil.example.com/", ["threshold"] = "info" });
        Assert.Throws<InvalidDataException>(() => AlertsFile.Open(edited.ToJsonString(), Hello));
    }

    [Test]
    public void A_mute_raised_threshold_or_removal_narrows_without_touching_the_sealed_file()
    {
        var text = AlertsFile.Seal(Config, 0, Hello, RecoveryPublic);
        var narrowing = new Dictionary<string, SinkNarrowing>
        {
            ["siem"] = new(Muted: true, Threshold: AlertSeverity.Critical),
            ["relay"] = new(Threshold: AlertSeverity.Info, Removed: false),
        };

        var setup = AlertsFile.Open(text, Hello).Config!.Setup(narrowing);

        Assert.That(setup.Sinks, Is.EqualTo(new[]
        {
            new SinkDefinition("siem", AlertSeverity.Critical, AlertRedaction.Trusted, Muted: true),
            new SinkDefinition("relay", AlertSeverity.Warning, AlertRedaction.Public),
        }), "a lower threshold in app.json can't widen");
        Assert.That(Config.Setup(new Dictionary<string, SinkNarrowing> { ["siem"] = new(Removed: true) }).Sinks.Select(s => s.Id), Is.EqualTo(new[] { "relay" }));
        Assert.That(Config.Purged(new Dictionary<string, SinkNarrowing> { ["siem"] = new(Removed: true) }).Sinks.Select(s => s.Id), Is.EqualTo(new[] { "relay" }));
    }

    [Test]
    public void A_newer_document_is_refused() =>
        Assert.Throws<InvalidDataException>(() => AlertsConfig.FromDocument(new JsonObject { ["v"] = 2, ["machine"] = "m" }));
}

public class AlertsCardTests
{
    static (WebhookSink? Sink, Phrase? Problem) Build(bool needsMachine = false, string machine = "", string id = "siem",
        string url = "https://hooks.example.com/t", string header = "", string value = "", string[]? existing = null) =>
        AlertsCard.Build(needsMachine, machine, id, url, header, value, AlertSeverity.High, false, existing ?? []);

    [Test]
    public void The_first_sink_needs_a_machine_label() =>
        Assert.That(Build(needsMachine: true, machine: "  ").Problem?.Key, Is.EqualTo("Alerts_NeedMachine"));

    [TestCase("Siem", "Alerts_BadId")]
    [TestCase("", "Alerts_BadId")]
    public void Ids(string id, string key) => Assert.That(Build(id: id).Problem?.Key, Is.EqualTo(key));

    [Test]
    public void A_taken_id_is_refused() => Assert.That(Build(existing: ["siem"]).Problem?.Key, Is.EqualTo("Alerts_IdTaken"));

    [TestCase("http://hooks.example.com/t", "Alerts_UrlNotHttps")]
    [TestCase("https://alice:pw@hooks.example.com/t", "Alerts_UrlUserInfo")]
    public void Urls(string url, string key) => Assert.That(Build(url: url).Problem?.Key, Is.EqualTo(key));

    [TestCase("Host", "x", "Alerts_HeaderReserved")]
    [TestCase("Bad Name", "x", "Alerts_HeaderName")]
    [TestCase("X-Api", "a\r\nb", "Alerts_HeaderValue")]
    public void Headers(string name, string value, string key) => Assert.That(Build(header: name, value: value).Problem?.Key, Is.EqualTo(key));

    [Test]
    public void A_good_form_is_a_sink()
    {
        var (sink, problem) = Build(needsMachine: true, machine: "desk", header: "Authorization", value: "Bearer t");
        Assert.That(problem, Is.Null);
        Assert.That((sink!.Id, sink.Url.Host, sink.Headers.Single().Key), Is.EqualTo(("siem", "hooks.example.com", "Authorization")));
    }

    [Test]
    public void Describes_the_card()
    {
        Assert.That(AlertsCard.Describe(false, null).Key, Is.EqualTo("Alerts_Locked"));
        Assert.That(AlertsCard.Describe(true, null).Key, Is.EqualTo("Alerts_None"));
        Assert.That(AlertsCard.Outcome("siem", new(DeliveryStatus.Stop, 401)), Is.EqualTo(new Phrase("Alerts_TestRefused", "siem", 401)).Using<Phrase>((a, b) => a.Key == b.Key && a.Args.SequenceEqual(b.Args)));
        Assert.That(AlertsCard.Outcome("siem", new(DeliveryStatus.Retry, Error: "Timeout")).Key, Is.EqualTo("Alerts_TestTimeout"));
    }
}
