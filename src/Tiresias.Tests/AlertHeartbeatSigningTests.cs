using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class WebhookSignatureTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);

    /// <summary>The secret's key bytes spell a canary, so a key that leaked in any encoding is easy to find.</summary>
    static readonly string Secret = WebhookSignature.SecretPrefix + Convert.ToBase64String(Encoding.ASCII.GetBytes("CANARY-signing-key-0123456789ab"));

    static readonly AlertPayload Payload = new("01JD2K8Q4X9V7M3N5P6R8S0T2W", "decoy.used", AlertSeverity.Critical, "Decoy credential used",
        "workstation", T0, 1, "decoy.used:5e1f0c9a2b7d4e86", null);

    static readonly WebhookSink Sink = new("siem", new("https://hooks.example.com/t"), [new("Authorization", "Bearer CANARY-header-secret")], Signing: Secret);

    /// <summary>What a receiver does (standardwebhooks.com): HMAC-SHA-256 over <c>id.timestamp.body</c>, compared in constant time.</summary>
    static bool Verify(string secret, FakeHandler.Captured sent, DateTimeOffset receiverNow)
    {
        var key = Convert.FromBase64String(secret[WebhookSignature.SecretPrefix.Length..]);
        var id = sent.Header("webhook-id");
        var timestamp = long.Parse(sent.Header("webhook-timestamp"), System.Globalization.CultureInfo.InvariantCulture);
        if (Math.Abs(receiverNow.ToUnixTimeSeconds() - timestamp) > WebhookSignature.Tolerance.TotalSeconds)
            return false;
        var signed = Encoding.UTF8.GetBytes($"{id}.{timestamp}.").Concat(sent.Body).ToArray();
        var expected = Encoding.ASCII.GetBytes("v1," + Convert.ToBase64String(HMACSHA256.HashData(key, signed)));
        return sent.Header("webhook-signature").Split(' ').Any(s => CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(s), expected));
    }

    [Test]
    public void Matches_the_standard_webhooks_test_vector()
    {
        // The vector the Standard Webhooks reference libraries test against.
        Assert.That(WebhookSignature.TryParseSecret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", out var key), Is.True);
        Assert.That(WebhookSignature.Sign(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, "{\"test\": 2432232314}"u8),
            Is.EqualTo("v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="));
    }

    [TestCase("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", true)]
    [TestCase("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", false)]
    [TestCase("whsec_c2hvcnQ=", false)]
    [TestCase("whsec_not base64!", false)]
    [TestCase("", false)]
    public void Secrets(string secret, bool valid)
    {
        Assert.That(WebhookSignature.TryParseSecret(secret, out _), Is.EqualTo(valid));
        Assert.That(SinkRules.CheckSigning(secret), Is.EqualTo(valid ? SinkProblem.None : SinkProblem.Signing));
    }

    [Test]
    public void A_new_secret_is_one_a_receiver_takes() =>
        Assert.That(WebhookSignature.TryParseSecret(WebhookSignature.NewSecret(), out var key) && key.Length == 32, Is.True);

    [Test]
    public async Task A_signed_request_verifies_and_each_retry_signs_again_with_its_own_time()
    {
        var handler = FakeHandler.Always(HttpStatusCode.ServiceUnavailable);
        var time = new SteppedTime(T0);
        using var transport = new HttpAlertTransport(handler, time);
        await transport.DeliverAsync(Payload, Sink, CancellationToken.None);
        time.Advance(TimeSpan.FromMinutes(7));
        await transport.DeliverAsync(Payload, Sink, CancellationToken.None);

        var (first, second) = (handler.Requests.First(), handler.Requests.Last());
        Assert.That(Verify(Secret, first, T0), Is.True);
        Assert.That(Verify(Secret, second, T0.AddMinutes(7)), Is.True);
        Assert.That(Verify(Secret, first, T0.AddMinutes(7)), Is.False, "a replay outside the tolerance fails");
        Assert.That(Verify(WebhookSignature.NewSecret(), first, T0), Is.False);
        Assert.That(first.Header("webhook-id"), Is.EqualTo(Payload.Id).And.EqualTo(second.Header("webhook-id")).And.EqualTo(first.Header("Idempotency-Key")));
        Assert.That(first.Header("webhook-timestamp"), Is.EqualTo(T0.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    [Test]
    public async Task The_signing_key_never_leaves_and_an_unsigned_sink_sends_no_signature()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        using var transport = new HttpAlertTransport(handler, new SteppedTime(T0));
        await transport.DeliverAsync(Payload, Sink, CancellationToken.None);
        await transport.DeliverAsync(Payload, Sink with { Signing = null }, CancellationToken.None);

        var (signed, unsigned) = (handler.Requests.First(), handler.Requests.Last());
        Assert.That(signed.Wire, Does.Not.Contain(Secret).And.Not.Contain(Secret[WebhookSignature.SecretPrefix.Length..]).And.Not.Contain("CANARY-signing"));
        Assert.That(unsigned.Headers.Select(h => h.Key), Has.None.StartsWith("webhook-"));
        Assert.That($"{Sink} {new AlertsConfig("workstation", new byte[32], [Sink])}", Does.Not.Contain("whsec").And.Not.Contain("CANARY"));
    }

    [TestCase("webhook-signature")]
    [TestCase("Webhook-Timestamp")]
    [TestCase("webhook-id")]
    public void A_user_header_cannot_fake_a_signature(string name) =>
        Assert.That(SinkRules.CheckHeader(name, "v1,x"), Is.EqualTo(SinkProblem.HeaderReserved));

    [Test]
    public async Task A_bad_secret_is_never_sent()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        using var transport = new HttpAlertTransport(handler, new SteppedTime(T0));
        var result = await transport.DeliverAsync(Payload, Sink with { Signing = "whsec_c2hvcnQ=" }, CancellationToken.None);

        Assert.That(handler.Requests, Is.Empty);
        Assert.That((result.Status, result.Error), Is.EqualTo((DeliveryStatus.Stop, nameof(SinkProblem.Signing))));
    }
}

public class HeartbeatTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];
    static readonly TimeSpan Every = TimeSpan.FromMinutes(15);

    static AlertSetup Setup(params SinkDefinition[] sinks) => new("workstation", InstallKey, sinks);

    static IEnumerable<Delivery> Alive(AlertPlan plan) => plan.Now.Where(d => d.Payload.Event == "alerts.alive");

    [Test]
    public void The_first_goes_at_once_then_one_per_interval()
    {
        var setup = Setup(new SinkDefinition("siem", AlertSeverity.High, Heartbeat: Every));
        var state = AlertState.Empty;
        var sent = new List<DateTimeOffset>();
        for (var minute = 0; minute <= 60; minute++)
        {
            var now = T0.AddMinutes(minute);
            var plan = AlertPlanner.Tick(setup, state, now);
            state = plan.Next;
            sent.AddRange(Alive(plan).Select(d => d.Payload.At));
        }

        Assert.That(sent, Is.EqualTo(new[] { T0, T0.AddMinutes(15), T0.AddMinutes(30), T0.AddMinutes(45), T0.AddMinutes(60) }));
    }

    [Test]
    public void Only_to_sinks_that_opted_in_and_are_not_muted()
    {
        var setup = Setup(
            new SinkDefinition("on", AlertSeverity.Critical, Heartbeat: Every),
            new SinkDefinition("off", AlertSeverity.Info),
            new SinkDefinition("muted", AlertSeverity.Info, Muted: true, Heartbeat: Every));

        Assert.That(Alive(AlertPlanner.Tick(setup, AlertState.Empty, T0)).Select(d => d.SinkId), Is.EqualTo(new[] { "on" }),
            "a heartbeat ignores the threshold: it is about the sink, not an event");
    }

    [Test]
    public void It_spends_no_rate_limit_and_is_not_deduped()
    {
        var setup = Setup(new SinkDefinition("siem", AlertSeverity.High, Heartbeat: TimeSpan.FromMinutes(5)));
        var state = AlertState.Empty;
        for (var minute = 0; minute < 60; minute += 5)
            state = AlertPlanner.Tick(setup, state, T0.AddMinutes(minute)).Next;

        var plan = AlertPlanner.Plan(new(AlertKind.ProgramBlocked, new(Program: "C:\\x.exe"), T0.AddMinutes(60)), setup, state, T0.AddMinutes(60));
        Assert.That(plan.Now.Select(d => d.Payload.Event), Is.EquivalentTo(new[] { "alerts.alive", "program.blocked" }));
    }

    [Test]
    public void Unmuting_sends_one_at_once()
    {
        var on = Setup(new SinkDefinition("siem", AlertSeverity.High, Heartbeat: Every));
        var muted = Setup(new SinkDefinition("siem", AlertSeverity.High, Muted: true, Heartbeat: Every));
        var state = AlertPlanner.Tick(on, AlertState.Empty, T0).Next;
        state = AlertPlanner.Tick(muted, state, T0.AddMinutes(1)).Next;

        Assert.That(Alive(AlertPlanner.Tick(on, state, T0.AddMinutes(2))), Has.Exactly(1).Items);
    }

    [TestCase(AlertRedaction.Public)]
    [TestCase(AlertRedaction.Trusted)]
    public void It_carries_the_label_and_the_time_only(AlertRedaction redaction)
    {
        var setup = Setup(new SinkDefinition("siem", AlertSeverity.High, redaction, Heartbeat: Every));
        var payload = Alive(AlertPlanner.Tick(setup, AlertState.Empty, T0)).Single().Payload;
        var json = JsonNode.Parse(AlertWire.Serialize(payload))!.AsObject();

        Assert.That(json.Select(p => p.Key), Is.EquivalentTo(new[] { "schema", "id", "event", "severity", "title", "machine", "at", "count", "key" }));
        Assert.That((payload.Event, payload.Severity, payload.Title, payload.Machine, payload.At, payload.Count, payload.Detail),
            Is.EqualTo(("alerts.alive", AlertSeverity.Info, "Tiresias is running", "workstation", T0, 1, (TrustedDetail?)null)));
    }

    [TestCase(5, SinkProblem.None)]
    [TestCase(60, SinkProblem.None)]
    [TestCase(4, SinkProblem.Heartbeat)]
    [TestCase(61, SinkProblem.Heartbeat)]
    public void Intervals(int minutes, SinkProblem expected) =>
        Assert.That(SinkRules.CheckHeartbeat(TimeSpan.FromMinutes(minutes)), Is.EqualTo(expected));

    [Test]
    public void A_waiting_heartbeat_gives_way_to_a_newer_one()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        var sender = new AlertSender(new HttpAlertTransport(handler, time), time, _ => { });
        sender.Configure([new WebhookSink("siem", new("https://hooks.example.com/t"), [])]);
        AlertPayload Alive(string id) => new(id, "alerts.alive", AlertSeverity.Info, "Tiresias is running", "workstation", T0, 1, "alerts.alive:00", null);
        AlertPayload Decoy = new("D", "decoy.used", AlertSeverity.Critical, "Decoy credential used", "workstation", T0, 1, "decoy.used:00", null);

        // Not started: everything waits, as behind a receiver that is down.
        sender.Enqueue(new("siem", Alive("A1")));
        sender.Enqueue(new("siem", Decoy));
        sender.Enqueue(new("siem", Alive("A2")));

        Assert.That(sender.Waiting("siem"), Is.EqualTo(2), "the decoy and the newest heartbeat");
    }

    [Test]
    public async Task The_center_sends_the_first_at_unlock_and_the_next_when_due()
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Start();
        var sink = new WebhookSink("siem", new("https://hooks.example.com/t"), [], Heartbeat: Every);
        center.Use(new("workstation", InstallKey, [sink, new WebhookSink("quiet", new("https://hooks.example.com/q"), [])]), null);
        await Until(() => handler.Requests.Count == 1);

        time.Advance(TimeSpan.FromMinutes(14));
        await Task.Delay(50);
        Assert.That(handler.Requests, Has.Count.EqualTo(1));
        time.Advance(TimeSpan.FromMinutes(1));
        await Until(() => handler.Requests.Count == 2);

        Assert.That(handler.Requests.Select(r => r.Url.AbsolutePath), Is.All.EqualTo("/t"));
        Assert.That(handler.Requests.Select(r => AlertWire.Parse(r.Body).Event), Is.All.EqualTo("alerts.alive"));
    }

    static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
            await Task.Delay(10);
        Assert.That(condition(), Is.True, "timed out");
    }
}

public class SignedHeartbeatConfigTests
{
    [Test]
    public void Signing_and_heartbeat_round_trip_through_alerts_json()
    {
        var secret = WebhookSignature.NewSecret();
        var config = new AlertsConfig("workstation", new byte[32],
            [new WebhookSink("siem", new("https://hooks.example.com/t"), [], Signing: secret, Heartbeat: TimeSpan.FromMinutes(15))]);

        var back = AlertsConfig.FromDocument(config.ToDocument())!;
        var sink = (WebhookSink)back.Sinks.Single();
        Assert.That((sink.Signing, sink.Heartbeat), Is.EqualTo((secret, (TimeSpan?)TimeSpan.FromMinutes(15))));
        Assert.That(back.Setup(null).Sinks.Single().Heartbeat, Is.EqualTo(TimeSpan.FromMinutes(15)));
        Assert.That(config.ToDocument().ToJsonString(), Does.Not.Contain("heartbeat\":null").And.Not.Contain("signing\":null"));
    }

    [Test]
    public void A_new_signing_secret_restarts_a_stopped_sink()
    {
        var a = new WebhookSink("siem", new("https://hooks.example.com/t"), [], Signing: WebhookSignature.NewSecret());
        Assert.That(a.SameTarget(a with { Signing = WebhookSignature.NewSecret() }), Is.False);
        Assert.That(a.SameTarget(a with { Heartbeat = TimeSpan.FromMinutes(5) }), Is.True);
    }

    [Test]
    public void The_form_checks_the_secret_and_the_heartbeat()
    {
        (WebhookSink? Sink, Phrase? Problem) Build(string signing, int minutes) =>
            AlertsCard.Build(false, "", "siem", "https://hooks.example.com/t", "", "", AlertSeverity.High, false, [], signing, minutes);

        Assert.That(Build("whsec_c2hvcnQ=", 0).Problem?.Key, Is.EqualTo("Alerts_SigningBad"));
        Assert.That(Build("", 3).Problem?.Key, Is.EqualTo("Alerts_HeartbeatBad"));
        var (sink, problem) = Build("  whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw ", 15);
        Assert.That(problem, Is.Null);
        Assert.That((sink!.Signing, sink.Heartbeat), Is.EqualTo(("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", (TimeSpan?)TimeSpan.FromMinutes(15))));
        var plain = Build("", 0).Sink!;
        Assert.That((plain.Signing, plain.Heartbeat), Is.EqualTo(((string?)null, (TimeSpan?)null)));
        Assert.That(AlertsCard.HeartbeatChoices.Skip(1).Select(m => SinkRules.CheckHeartbeat(TimeSpan.FromMinutes(m))), Is.All.EqualTo(SinkProblem.None));
    }
}
