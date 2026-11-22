using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Protocol;

namespace Tiresias.Tests;

/// <summary>Phase 6 of docs/alerts.md: a sink that stops delivering is a finding on Home and an <c>alerts.failing</c> to the others.</summary>
public class SinkHealthTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);

    [Test]
    public void Failing_starts_15_minutes_after_the_first_failed_attempt()
    {
        var failure = SinkHealth.After(null, DeliveryStatus.Retry, T0);
        failure = SinkHealth.After(failure, DeliveryStatus.Retry, T0.AddMinutes(8));

        Assert.That(failure, Is.EqualTo(new SinkFailure(T0, false)), "kept from the first failure");
        Assert.That(SinkHealth.IsFailing(failure, T0.AddMinutes(15) - TimeSpan.FromTicks(1)), Is.False);
        Assert.That(SinkHealth.IsFailing(failure, T0.AddMinutes(15)), Is.True);
    }

    [Test]
    public void A_stop_is_failing_at_once()
    {
        var failure = SinkHealth.After(null, DeliveryStatus.Stop, T0);
        Assert.That(SinkHealth.IsFailing(failure, T0), Is.True);
        Assert.That(failure!.Stopped, Is.True);
        Assert.That(SinkHealth.After(new(T0.AddMinutes(-3), false), DeliveryStatus.Stop, T0), Is.EqualTo(new SinkFailure(T0.AddMinutes(-3), true)));
    }

    [Test]
    public void A_delivery_clears_it()
    {
        Assert.That(SinkHealth.After(new(T0, true), DeliveryStatus.Delivered, T0.AddHours(1)), Is.Null);
        Assert.That(SinkHealth.IsFailing(null, T0), Is.False);
    }

    [Test]
    public void Only_a_sink_that_wasnt_failing_before_is_newly_failing()
    {
        FailingSink a = new("a", false), b = new("b", true);
        Assert.That(SinkHealth.NewlyFailing([a], [a, b]), Is.EqualTo(new[] { b }));
        Assert.That(SinkHealth.NewlyFailing([a, b], [a with { Stopped = true }]), Is.Empty, "a stop after failing is the same failure");
    }
}

public class AlertsFailingPlannerTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    static AlertSetup Setup(params SinkDefinition[] sinks) => new("workstation", InstallKey, sinks);

    [Test]
    public void Goes_to_the_other_sinks_whatever_their_threshold_and_never_to_the_failing_one()
    {
        var setup = Setup(new("phone", AlertSeverity.High), new("siem", AlertSeverity.Critical), new("desk", AlertSeverity.Warning),
            new("muted", AlertSeverity.Info, Muted: true));
        var plan = AlertPlanner.Plan(AlertSources.AlertsFailing(new("phone", false), T0), setup, AlertState.Empty, T0);

        Assert.That(plan.Now.Select(d => d.SinkId), Is.EquivalentTo(new[] { "siem", "desk" }));
        Assert.That(plan.Now.Select(d => d.Payload.Event), Is.All.EqualTo("alerts.failing"));
    }

    [Test]
    public void A_public_sink_gets_the_event_alone_and_a_trusted_one_the_sink_id()
    {
        var setup = Setup(new("public", AlertSeverity.High), new("trusted", AlertSeverity.High, AlertRedaction.Trusted));
        var plan = AlertPlanner.Plan(AlertSources.AlertsFailing(new("canary-sink-1", true), T0), setup, AlertState.Empty, T0);

        var open = plan.Now.Single(d => d.SinkId == "public").Payload;
        Assert.That(open.Detail, Is.Null);
        Assert.That(Encoding.UTF8.GetString(AlertWire.Serialize(open)), Does.Not.Contain("canary"));
        Assert.That(plan.Now.Single(d => d.SinkId == "trusted").Payload.Detail, Is.EqualTo(new TrustedDetail(What: "canary-sink-1")));
    }

    [Test]
    public void Each_failing_sink_has_its_own_key_and_other_subjects_keep_theirs()
    {
        Assert.That(AlertPlanner.KeyFor("alerts.failing", new(Sink: "a"), InstallKey), Is.Not.EqualTo(AlertPlanner.KeyFor("alerts.failing", new(Sink: "b"), InstallKey)));
        // The golden key of docs/alerts.md, unchanged by the new field.
        Assert.That(AlertPlanner.KeyFor("decoy.used", new(What: "x"), InstallKey),
            Is.EqualTo(AlertPlanner.KeyFor("decoy.used", new(What: "x", Sink: null), InstallKey)));
    }
}

public class AlertsFailingCenterTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    const string UrlSecret = "CANARY-url-secret";
    const string HeaderSecret = "CANARY-header-secret";
    const string TokenSecret = "CANARY-ntfy-token";
    const string FailingHost = "failing.example.net";

    /// <summary>The sink that fails: its address, header and id are canaries.</summary>
    static readonly WebhookSink Failing = new("canary-sink-1", new($"https://{FailingHost}/hook?key={UrlSecret}"),
        [new("Authorization", $"Bearer {HeaderSecret}")], AlertSeverity.High);

    static WebhookSink Other(AlertRedaction redaction) =>
        new("other", new("https://hooks.example.com/other"), [], AlertSeverity.High, redaction);

    static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 500 && !condition(); i++)
            await Task.Delay(10);
        Assert.That(condition(), Is.True, "timed out");
    }

    /// <summary>Moves the clock a minute at a time, so the worker's backoff and the center's tick both run.</summary>
    static async Task Pass(SteppedTime time, TimeSpan span)
    {
        for (var passed = TimeSpan.Zero; passed < span; passed += TimeSpan.FromMinutes(1))
        {
            await Task.Delay(20);
            time.Advance(TimeSpan.FromMinutes(1));
        }
        await Task.Delay(50);
    }

    static IEnumerable<AlertPayload> Sent(FakeHandler handler, string host) =>
        handler.Requests.Where(r => r.Url.Host == host && r.Body.Length > 0 && r.Body[0] == '{').Select(r => AlertWire.Parse(r.Body));

    sealed class Fixture : IAsyncDisposable
    {
        public readonly SteppedTime Time = new(T0);
        public readonly ConcurrentQueue<string> Log = new();
        public volatile HttpStatusCode FailingAnswer = HttpStatusCode.InternalServerError;
        public readonly FakeHandler Handler;
        public readonly AlertCenter Center;
        public int Changes;

        public Fixture()
        {
            Handler = new((request, _) => new HttpResponseMessage(request.RequestUri!.Host == FailingHost ? FailingAnswer : HttpStatusCode.OK));
            Center = new(new HttpAlertTransport(Handler, Time), Time, Log.Enqueue);
            Center.FailingChanged += () => Interlocked.Increment(ref Changes);
            Center.Start();
        }

        public ValueTask DisposeAsync() => Center.DisposeAsync();
    }

    [Test]
    public async Task Failing_for_15_minutes_is_a_finding_and_an_alert_to_the_others_until_it_delivers_again()
    {
        await using var f = new Fixture();
        f.Center.Use(new("workstation", InstallKey, [Failing, Other(AlertRedaction.Public)]), null);
        f.Center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));
        await Until(() => f.Handler.Requests.Count(r => r.Url.Host == FailingHost) == 1);

        await Pass(f.Time, TimeSpan.FromMinutes(14));
        Assert.That(f.Center.Failing, Is.Empty, "not before 15 minutes");

        await Pass(f.Time, TimeSpan.FromMinutes(2));
        await Until(() => f.Center.Failing.Count == 1);
        Assert.That(f.Center.Failing.Single(), Is.EqualTo(new FailingSink("canary-sink-1", false)));
        await Until(() => Sent(f.Handler, "hooks.example.com").Any(p => p.Event == "alerts.failing"));
        Assert.That(Sent(f.Handler, FailingHost).Select(p => p.Event), Has.None.EqualTo("alerts.failing"), "never to the failing sink");

        var finding = Doctor.FailingAlerts(f.Center.Failing).Single();
        Assert.That(finding.Name, Is.EqualTo("alerts to canary-sink-1 aren't arriving"));
        Assert.That(finding.IsFinding, Is.True);

        f.FailingAnswer = HttpStatusCode.OK;
        await Pass(f.Time, TimeSpan.FromMinutes(20));
        await Until(() => f.Center.Failing.Count == 0);
        Assert.That(f.Changes, Is.GreaterThanOrEqualTo(2), "it came and went");
    }

    [Test]
    public async Task A_stopped_sink_fails_at_once_and_clears_when_fixed_or_removed()
    {
        await using var f = new Fixture();
        f.FailingAnswer = HttpStatusCode.Unauthorized;
        var config = new AlertsConfig("workstation", InstallKey, [Failing, Other(AlertRedaction.Public)]);
        f.Center.Use(config, null);
        f.Center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));

        await Until(() => f.Center.Failing.Count == 1);
        Assert.That(f.Center.Failing.Single().Stopped, Is.True);
        await Until(() => Sent(f.Handler, "hooks.example.com").Any(p => p.Event == "alerts.failing"));

        // Fixed: a new address restarts the sink.
        f.FailingAnswer = HttpStatusCode.OK;
        f.Center.Use(new("workstation", InstallKey, [Failing with { Headers = [new("Authorization", "Bearer fixed")] }, Other(AlertRedaction.Public)]), null);
        await Until(() => f.Center.Failing.Count == 0);

        // Stopped again, then removed.
        f.FailingAnswer = HttpStatusCode.Forbidden;
        f.Center.Use(config, null);
        f.Center.Raise(new(AlertKind.ProgramBlocked, new(Program: "C:\\y.exe"), T0));
        await Until(() => f.Center.Failing.Count == 1);
        f.Center.Use(config, new Dictionary<string, SinkNarrowing> { ["canary-sink-1"] = new(Removed: true) });
        Assert.That(f.Center.Failing, Is.Empty);
    }

    [Test]
    public async Task A_test_alert_that_gets_through_clears_it()
    {
        await using var f = new Fixture();
        f.FailingAnswer = HttpStatusCode.NotFound;
        f.Center.Use(new("workstation", InstallKey, [Failing]), null);
        f.Center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));
        await Until(() => f.Center.Failing.Count == 1);

        f.FailingAnswer = HttpStatusCode.OK;
        Assert.That((await f.Center.SendTestAsync("canary-sink-1", CancellationToken.None))!.Status, Is.EqualTo(DeliveryStatus.Delivered));
        await Until(() => f.Center.Failing.Count == 0);
    }

    [Test]
    public async Task A_muted_sink_is_no_finding()
    {
        await using var f = new Fixture();
        f.FailingAnswer = HttpStatusCode.BadRequest;
        var config = new AlertsConfig("workstation", InstallKey, [Failing, Other(AlertRedaction.Public)]);
        f.Center.Use(config, null);
        f.Center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));
        await Until(() => f.Center.Failing.Count == 1);

        f.Center.Use(config, new Dictionary<string, SinkNarrowing> { ["canary-sink-1"] = new(Muted: true) });
        Assert.That(f.Center.Failing, Is.Empty);
    }

    // ---- Canary: nothing of the failing sink but its id, and that only in a trusted detail. ----

    [TestCase(AlertRedaction.Public)]
    [TestCase(AlertRedaction.Trusted)]
    public async Task No_url_header_or_token_of_the_failing_sink_reaches_any_output(AlertRedaction redaction)
    {
        await using var f = new Fixture();
        var ntfy = new NtfySink("phone", new("https://ntfy.example.com/alerts-topic"), TokenSecret, AlertSeverity.High, redaction);
        var failingNtfy = new NtfySink("canary-sink-2", new($"https://{FailingHost}/{UrlSecret}"), TokenSecret + "-2");
        f.FailingAnswer = HttpStatusCode.Unauthorized;
        f.Center.Use(new("workstation", InstallKey, [Failing, failingNtfy, Other(redaction), ntfy]), null);
        f.Center.Raise(new(AlertKind.DecoyUsed, new(Program: "C:\\x.exe"), T0));

        await Until(() => f.Center.Failing.Count == 2);
        await Until(() => f.Handler.Requests.Count(r => r.Url.Host != FailingHost && r.Wire.Contains("alerts", StringComparison.OrdinalIgnoreCase) && r.Wire.Contains("fail", StringComparison.OrdinalIgnoreCase)) >= 4);

        var outside = f.Handler.Requests.Where(r => r.Url.Host != FailingHost).ToList();
        var finding = string.Join("\n", Doctor.FailingAlerts(f.Center.Failing).Select(c => $"{c.Name} {c.Detail} {c.Fix?.Instruction}"));
        foreach (var text in outside.Select(r => r.Url + "\n" + r.Wire).Concat(f.Log).Append(finding))
            Assert.That(text, Does.Not.Contain(UrlSecret).And.Not.Contain(HeaderSecret).And.Not.Contain(TokenSecret + "-2").And.Not.Contain(FailingHost));

        var webhook = outside.Where(r => r.Url.Host == "hooks.example.com").Select(r => JsonNode.Parse(r.Body)!.AsObject())
            .Where(j => (string?)j["event"] == "alerts.failing").ToList();
        Assert.That(webhook, Has.Count.EqualTo(2));
        foreach (var json in webhook)
        {
            var detail = json["detail"]?.ToJsonString() ?? "";
            json.Remove("detail");
            Assert.That(json.ToJsonString(), Does.Not.Contain("canary-sink"), "the id only ever in detail");
            Assert.That(detail, redaction == AlertRedaction.Public ? Is.Empty : Does.Match("^\\{\"what\":\"canary-sink-[12]\"\\}$"));
        }
        var phone = outside.Where(r => r.Url.Host == "ntfy.example.com").Select(r => r.Wire).ToList();
        Assert.That(phone, Has.Some.Contains("Alerts to a sink are failing"));
        Assert.That(phone, Has.All.Not.Contains("canary-sink"), "an ntfy body never carries the id, trusted or not");
        Assert.That(finding, Does.Contain("canary-sink-1").And.Contain("canary-sink-2"));
    }
}

public class FailingAlertsFindingTests
{
    sealed class Probe : IDoctorProbe
    {
        public bool Enrolled => true;
        public bool HasDeviceKey => true;
        public bool RecoveryKeySet => true;
        public DoctorVault? Vault => new(0, [], []);
        public IReadOnlyList<FailingSink> FailingAlertSinks { get; init; } = [];
        public Task<int?> BrokerStatusAsync() => Task.FromResult<int?>(401);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(true);
        public IEnumerable<DoctorFile> UserSecretsFiles() => [];
        public IEnumerable<DoctorFile> Projects() => [];
    }

    [Test]
    public async Task Home_shows_one_finding_per_failing_sink_and_none_once_it_clears()
    {
        var checks = await Doctor.RunAsync(new Probe { FailingAlertSinks = [new("phone", false), new("siem", true)] });
        var findings = checks.Where(c => c.Kind == Doctor.AlertsKind).ToList();

        Assert.That(findings.Select(c => c.Name), Is.EqualTo(new[] { "alerts to phone aren't arriving", "alerts to siem aren't arriving" }));
        Assert.That(findings.Select(c => c.Status), Is.All.EqualTo(DoctorStatus.Fail));
        Assert.That(findings[0].Detail, Does.Contain("keeps trying"));
        Assert.That(findings[1].Detail, Does.Contain("refused"));
        Assert.That(findings.Select(c => FindingView.Button(c.Fix)?.Action), Is.All.EqualTo(FixAction.OpenAlerts));
        Assert.That(findings.Select(c => c.Fix), Is.EqualTo(new DoctorFix[] { new ReviewAlerts("phone"), new ReviewAlerts("siem") }));

        Assert.That((await Doctor.RunAsync(new Probe())).Where(c => c.Kind == Doctor.AlertsKind), Is.Empty);
    }

    [Test]
    public void A_stop_after_a_dismissed_failure_brings_the_finding_back() =>
        Assert.That(Doctor.FailingAlerts([new("phone", false)]).Single().Subject,
            Is.Not.EqualTo(Doctor.FailingAlerts([new("phone", true)]).Single().Subject));
}
