using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using NSec.Cryptography;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Decoys;
using Tiresias.Protocol;
using Tiresias.Vault;

namespace Tiresias.Tests;

/// <summary>The ntfy sink (docs/alerts.md, phase 3): rules, formatter, credentials and the canary. Never a real ntfy server.</summary>
public class AlertNtfyTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    const string TokenSecret = "tk_CANARY-ntfy-token";
    const string TopicSecret = "CANARY-topic";

    static NtfySink Sink(string id = "phone", AlertRedaction redaction = AlertRedaction.Public, string? token = TokenSecret) =>
        new(id, new($"https://ntfy.example.com/{TopicSecret}-{id}"), token, AlertSeverity.High, redaction);

    static AlertPayload Payload(AlertSeverity severity = AlertSeverity.Critical, TrustedDetail? detail = null) =>
        new("01JD2K8Q4X9V7M3N5P6R8S0T2W", "decoy.used", severity, "Decoy credential used", "workstation", T0, 3, "decoy.used:5e1f0c9a2b7d4e86", detail);

    /// <summary>The request line, headers and body, as the bytes on the wire would carry them.</summary>
    static string Wire(FakeHandler.Captured sent) => $"POST {sent.Url}\n{sent.Wire}";

    static async Task<(DeliveryResult Result, FakeHandler Handler)> Deliver(FakeHandler handler, AlertPayload? payload = null, NtfySink? sink = null)
    {
        using var transport = new HttpAlertTransport(handler, new SteppedTime(T0));
        return (await transport.DeliverAsync(payload ?? Payload(), sink ?? Sink(), CancellationToken.None), handler);
    }

    static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
            await Task.Delay(10);
        Assert.That(condition(), Is.True, "timed out");
    }

    // ---- Rules ----

    [TestCase("https://ntfy.sh", "abc", SinkProblem.None, "https://ntfy.sh/abc")]
    [TestCase("https://ntfy.sh/", "abc", SinkProblem.None, "https://ntfy.sh/abc")]
    [TestCase("https://example.com/ntfy/", "a-b_C9", SinkProblem.None, "https://example.com/ntfy/a-b_C9")]
    [TestCase("http://localhost:8080", "abc", SinkProblem.None, "http://localhost:8080/abc")]
    [TestCase("http://ntfy.example.com", "abc", SinkProblem.NotHttps, null)]
    [TestCase("https://alice:pw@ntfy.example.com", "abc", SinkProblem.UserInfo, null)]
    [TestCase("https://ntfy.example.com/?x=1", "abc", SinkProblem.Topic, null)]
    [TestCase("https://ntfy.example.com/#x", "abc", SinkProblem.Topic, null)]
    [TestCase("https://ntfy.example.com", "", SinkProblem.Topic, null)]
    [TestCase("https://ntfy.example.com", "a/b", SinkProblem.Topic, null)]
    [TestCase("https://ntfy.example.com", "a b", SinkProblem.Topic, null)]
    public void Server_and_topic(string server, string topic, SinkProblem expected, string? url)
    {
        Assert.That(SinkRules.CheckNtfy(server, topic, out var parsed), Is.EqualTo(expected));
        Assert.That(parsed?.ToString(), Is.EqualTo(url));
    }

    [Test]
    public void A_topic_is_at_most_64_characters() =>
        Assert.That(SinkRules.CheckNtfy("https://ntfy.sh", new string('a', 65), out _), Is.EqualTo(SinkProblem.Topic));

    [TestCase("tk_abc", SinkProblem.None)]
    [TestCase("tk abc", SinkProblem.Token)]
    [TestCase("tk_abc\r\nX-Evil: 1", SinkProblem.Token)]
    [TestCase("", SinkProblem.Token)]
    public void Tokens(string token, SinkProblem expected) => Assert.That(SinkRules.CheckToken(token), Is.EqualTo(expected));

    [Test]
    public async Task An_invalid_definition_is_never_sent()
    {
        var (result, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK), sink: Sink() with { Token = "a\r\nHost: evil.example.com" });
        var (query, _) = await Deliver(handler, sink: Sink() with { Topic = new("https://ntfy.example.com/t?auth=x") });

        Assert.That(handler.Requests, Is.Empty);
        Assert.That((result.Status, result.Error, query.Error), Is.EqualTo((DeliveryStatus.Stop, "Token", "Topic")));
    }

    // ---- Formatter ----

    [TestCase(AlertSeverity.Info, "2", "information_source")]
    [TestCase(AlertSeverity.Warning, "3", "large_orange_diamond")]
    [TestCase(AlertSeverity.High, "4", "warning")]
    [TestCase(AlertSeverity.Critical, "5", "rotating_light")]
    public async Task Severity_is_the_priority_and_the_tag(AlertSeverity severity, string priority, string tags)
    {
        var (result, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK), Payload(severity));

        var sent = handler.Requests.Single();
        Assert.That(result.Status, Is.EqualTo(DeliveryStatus.Delivered));
        Assert.That((sent.Header("Priority"), sent.Header("Tags")), Is.EqualTo((priority, tags)));
        Assert.That(Encoding.UTF8.GetString(sent.Body), Is.EqualTo($"{severity} on workstation, ×3. Open Tiresias."));
    }

    [Test]
    public async Task Posts_to_the_topic_with_the_title_and_the_payload_id_as_the_idempotency_key()
    {
        var (_, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK));

        var sent = handler.Requests.Single();
        Assert.That(sent.Url, Is.EqualTo(Sink().Topic));
        Assert.That(sent.Header("Title"), Is.EqualTo("Decoy credential used"));
        Assert.That(sent.Header("Idempotency-Key"), Is.EqualTo(Payload().Id));
        Assert.That(sent.Header("Content-Type"), Is.EqualTo("text/plain; charset=utf-8"));
        Assert.That(sent.Header("Authorization"), Is.EqualTo($"Bearer {TokenSecret}"));
    }

    [Test]
    public async Task An_open_topic_sends_no_authorization()
    {
        var (_, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK), sink: Sink(token: null));
        Assert.That(handler.Requests.Single().Headers.Select(h => h.Key), Has.None.EqualTo("Authorization"));
    }

    [Test]
    public void A_trusted_body_names_the_program_file_only() =>
        Assert.That(NtfyFormat.Body(Payload(detail: new(Program: "C:\\Users\\alice\\tools\\x.exe", ProcessId: 4242, What: "the decoy admin token"))),
            Is.EqualTo("Critical on workstation, ×3 (x.exe). Open Tiresias."));

    [Test]
    public void Every_title_fits_a_header_as_is()
    {
        var titles = typeof(AlertKind).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(AlertKind))
            .Select(f => ((AlertKind)f.GetValue(null)!).Title).ToList();
        Assert.That(titles, Is.Not.Empty);
        Assert.That(titles, Has.All.Matches<string>(t => t.All(c => c is >= ' ' and < (char)0x7F)));
    }

    // ---- Credentials ----

    [Test]
    public async Task The_token_travels_only_in_the_authorization_header()
    {
        var (_, handler) = await Deliver(FakeHandler.Always(HttpStatusCode.OK));

        var sent = handler.Requests.Single();
        Assert.That(Regex.Matches(Wire(sent), "CANARY-ntfy-token").Count, Is.EqualTo(1));
        Assert.That(Encoding.UTF8.GetString(sent.Body), Does.Not.Contain("CANARY"));
        Assert.That(sent.Url.ToString(), Does.Not.Contain("token"));
        Assert.That(sent.Headers.Where(h => h.Key != "Authorization").Select(h => h.Value), Has.None.Contains("CANARY"));
    }

    [Test]
    public async Task A_failure_reports_the_exception_type_only()
    {
        var (result, _) = await Deliver(new((request, _) => throw new HttpRequestException($"Failed {request.RequestUri} {request.Headers.Authorization}")));

        Assert.That(result.Error, Is.EqualTo(nameof(HttpRequestException)));
        Assert.That(result.ToString(), Does.Not.Contain("CANARY").And.Not.Contain("example.com"));
    }

    [Test]
    public async Task Logs_never_carry_the_topic_or_the_token()
    {
        var time = new SteppedTime(T0);
        var handler = new FakeHandler((request, n) => n == 1
            ? throw new HttpRequestException($"Failed {request.RequestUri} {request.Headers.Authorization}")
            : new HttpResponseMessage(HttpStatusCode.Forbidden));
        var log = new ConcurrentQueue<string>();
        await using var sender = new AlertSender(new HttpAlertTransport(handler, time), time, log.Enqueue);
        sender.Configure([Sink()]);
        sender.Start();
        sender.Enqueue(new("phone", Payload()));
        await Until(() => handler.Requests.Count == 1 && log.Count == 1 && time.Pending == 1);
        time.Advance(TimeSpan.FromSeconds(30));
        await Until(() => sender.IsStopped("phone"));

        Assert.That(log, Has.Count.EqualTo(2));
        Assert.That(log, Has.All.Not.Contains("CANARY").And.All.Not.Contains("example.com").And.All.Not.Contains("Bearer"));
        Assert.That($"{Sink()} {new AlertsConfig("workstation", InstallKey, [Sink()])}", Does.Not.Contain("CANARY").And.Not.Contain("example.com"));
    }

    // ---- Canary through the decoy mapping, the planner and the ntfy formatter, as captured bytes. ----

    [TestCase(AlertRedaction.Public)]
    [TestCase(AlertRedaction.Trusted)]
    public async Task No_value_or_token_leaves_and_a_trusted_sink_gets_the_program_file_name_only(AlertRedaction redaction)
    {
        const string Value = "CANARY-value";
        const string Placeholder = "CANARY-placeholder";
        var hit = new DecoyHit(DecoyUse.AdminToken, $"http://127.0.0.1:5999/admin?token={Value}&placeholder={Placeholder}", 4242,
            "C:\\Users\\alice\\CANARY-1\\CANARY-5.exe", T0);
        var alert = AlertSources.DecoyUsed(hit, ["CANARY-2.exe (7)", "CANARY-3.exe (8)"], "CANARY-4")!;

        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        var log = new ConcurrentQueue<string>();
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, log.Enqueue);
        center.Start();
        center.Use(new("workstation", InstallKey, [Sink(redaction: redaction)]), null);
        center.Raise(alert);
        await Until(() => handler.Requests.Count == 1);

        var sent = handler.Requests.Single();
        var wire = Wire(sent);
        Assert.That(wire, Does.Not.Contain(Value).And.Not.Contain(Placeholder).And.Not.Contain("alice").And.Not.Contain("4242"));
        Assert.That(Regex.Matches(wire, "CANARY-ntfy-token").Count, Is.EqualTo(1), "the token once, in its header");
        Assert.That(log, Has.All.Not.Contains("CANARY"));
        var canaries = Regex.Matches(wire, "CANARY-\\d").Select(m => m.Value).Distinct();
        Assert.That(canaries, redaction == AlertRedaction.Public ? Is.Empty : Is.EquivalentTo(new[] { "CANARY-5" }));
        if (redaction == AlertRedaction.Trusted)
            Assert.That(Encoding.UTF8.GetString(sent.Body), Does.Contain("(CANARY-5.exe)"));
    }

    [Test]
    public async Task A_test_alert_reaches_the_topic()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Use(new("workstation", InstallKey, [Sink()]), null);

        var result = await center.SendTestAsync("phone", CancellationToken.None);

        var sent = handler.Requests.Single();
        Assert.That(result!.Status, Is.EqualTo(DeliveryStatus.Delivered));
        Assert.That((sent.Header("Title"), sent.Header("Priority")), Is.EqualTo(("Test alert", "2")));
        Assert.That(Encoding.UTF8.GetString(sent.Body), Is.EqualTo("Info on workstation, ×1. Open Tiresias."));
    }

    // ---- Sealed config ----

    [Test]
    public void Round_trips_sealed_with_no_topic_or_token_in_the_file()
    {
        var hello = X25519KeyWrapper.ForKey("hello", Key.Create(KeyAgreementAlgorithm.X25519));
        var recovery = X25519KeyWrapper.ForKey("recovery", Key.Create(KeyAgreementAlgorithm.X25519));
        var config = new AlertsConfig("workstation", InstallKey, [Sink(redaction: AlertRedaction.Trusted), Sink("open", token: null)]);

        var text = AlertsFile.Seal(config, 0, hello, recovery);
        var back = AlertsFile.Open(text, hello).Config!;

        Assert.That(text, Does.Not.Contain("CANARY").And.Not.Contain("example.com"));
        Assert.That(back.Sinks, Is.EqualTo(config.Sinks));
        Assert.That(back.Sinks.Cast<NtfySink>().Select(s => s.Token), Is.EqualTo(new[] { TokenSecret, null }));
    }

    [Test]
    public void A_webhook_and_ntfy_never_share_a_target() =>
        Assert.That(Sink().SameTarget(new WebhookSink("phone", Sink().Topic, [])), Is.False);

    // ---- The form ----

    static (NtfySink? Sink, Phrase? Problem) Build(string server = "https://ntfy.sh", string topic = "tiresias-a8f3k2m9q7x1", string token = "",
        bool needsMachine = false, string machine = "", string[]? existing = null) =>
        AlertsCard.BuildNtfy(needsMachine, machine, "phone", server, topic, token, AlertSeverity.High, false, existing ?? []);

    [Test]
    public void A_good_form_is_a_sink()
    {
        var (sink, problem) = Build(token: " tk_abc ");
        Assert.That(problem, Is.Null);
        Assert.That((sink!.Id, sink.Topic.ToString(), sink.Token, sink.Threshold), Is.EqualTo(("phone", "https://ntfy.sh/tiresias-a8f3k2m9q7x1", "tk_abc", AlertSeverity.High)));
        Assert.That(Build().Sink!.Token, Is.Null, "no token is an open topic");
    }

    [TestCase("http://ntfy.example.com", "t", "", "Alerts_UrlNotHttps")]
    [TestCase("https://ntfy.sh", "a/b", "", "Alerts_NtfyTopicBad")]
    [TestCase("https://ntfy.sh?x=1", "t", "", "Alerts_NtfyTopicBad")]
    [TestCase("https://ntfy.sh", "t", "tk a", "Alerts_NtfyTokenBad")]
    public void Problems(string server, string topic, string token, string key) =>
        Assert.That(Build(server, topic, token).Problem?.Key, Is.EqualTo(key));

    [Test]
    public void The_first_sink_needs_a_machine_label_and_ids_stay_unique()
    {
        Assert.That(Build(needsMachine: true).Problem?.Key, Is.EqualTo("Alerts_NeedMachine"));
        Assert.That(Build(existing: ["phone"]).Problem?.Key, Is.EqualTo("Alerts_IdTaken"));
    }
}
