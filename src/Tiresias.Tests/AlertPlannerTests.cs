using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Tiresias.Alerts;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AlertPlannerTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    static AlertSetup Setup(params SinkDefinition[] sinks) => new("workstation", InstallKey, sinks);

    static readonly SinkDefinition Phone = new("phone", AlertSeverity.High);
    static readonly SinkDefinition Siem = new("siem", AlertSeverity.Info, AlertRedaction.Trusted);

    static AlertEvent Event(AlertKind kind, string program = "C:\\x.exe", DateTimeOffset? at = null) =>
        new(kind, new(Program: program, ProcessId: 42), at ?? T0);

    /// <summary>Feeds events one after another, each at its own time, collecting every delivery.</summary>
    sealed class Driver(AlertSetup setup)
    {
        public AlertSetup Setup = setup;
        public AlertState State = AlertState.Empty;
        public readonly List<Delivery> Sent = [];

        public IReadOnlyList<Delivery> Plan(AlertEvent e) => Keep(AlertPlanner.Plan(e, Setup, State, e.At));

        public IReadOnlyList<Delivery> Tick(DateTimeOffset now) => Keep(AlertPlanner.Tick(Setup, State, now));

        IReadOnlyList<Delivery> Keep(AlertPlan plan)
        {
            State = plan.Next;
            Sent.AddRange(plan.Now);
            return plan.Now;
        }
    }

    [Test]
    public void A_sink_gets_nothing_below_its_threshold()
    {
        var plan = AlertPlanner.Plan(Event(AlertKind.FindingsFailing), Setup(Phone, Siem), AlertState.Empty, T0);
        Assert.That(plan.Now.Select(d => d.SinkId), Is.EqualTo(new[] { "siem" }));

        plan = AlertPlanner.Plan(Event(AlertKind.ProgramBlocked), Setup(Phone, Siem), AlertState.Empty, T0);
        Assert.That(plan.Now.Select(d => d.SinkId), Is.EqualTo(new[] { "phone", "siem" }));
    }

    [Test]
    public void A_muted_sink_gets_nothing_and_keeps_no_state()
    {
        var driver = new Driver(Setup(Phone with { Muted = true }));
        Assert.That(driver.Plan(Event(AlertKind.DecoyUsed)), Is.Empty);
        Assert.That(driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(1))), Is.Empty);
        Assert.That(driver.Tick(T0.AddHours(1)), Is.Empty);
        Assert.That(driver.State.Sinks, Is.Empty);
    }

    [Test]
    public void Muting_drops_pending_summaries_so_unmuting_replays_nothing()
    {
        var driver = new Driver(Setup(Phone));
        driver.Plan(Event(AlertKind.DecoyUsed));
        driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(1)));
        driver.Setup = Setup(Phone with { Muted = true });
        Assert.That(driver.Tick(T0.AddMinutes(2)), Is.Empty);
        driver.Setup = Setup(Phone);
        Assert.That(driver.Tick(T0.AddMinutes(30)), Is.Empty);
    }

    [Test]
    public void Repeats_within_the_window_are_one_alert_then_a_count()
    {
        var driver = new Driver(Setup(Phone));
        Assert.That(driver.Plan(Event(AlertKind.DecoyUsed)), Has.Count.EqualTo(1));
        Assert.That(driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(2))), Is.Empty);
        Assert.That(driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(3))), Is.Empty);
        Assert.That(driver.Tick(T0.AddMinutes(9)), Is.Empty);

        var summary = driver.Tick(T0.AddMinutes(10)).Single().Payload;
        Assert.That(summary.Count, Is.EqualTo(2));
        Assert.That(summary.At, Is.EqualTo(T0.AddMinutes(2)));
        Assert.That(summary.Key, Is.EqualTo(driver.Sent[0].Payload.Key));
        Assert.That(summary.Id, Is.Not.EqualTo(driver.Sent[0].Payload.Id));

        // The window closed: the next one goes out at once.
        Assert.That(driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(11))).Single().Payload.Count, Is.EqualTo(1));
    }

    [Test]
    public void A_window_without_repeats_closes_silently()
    {
        var driver = new Driver(Setup(Phone));
        driver.Plan(Event(AlertKind.DecoyUsed));
        Assert.That(driver.Tick(T0.AddMinutes(30)), Is.Empty);
    }

    [Test]
    public void Plan_flushes_a_closed_window_even_when_nobody_ticked()
    {
        var driver = new Driver(Setup(Phone));
        driver.Plan(Event(AlertKind.DecoyUsed));
        driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(1)));
        var sent = driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(20)));
        Assert.That(sent.Select(d => d.Payload.Count), Is.EqualTo(new[] { 1, 1 }));
        Assert.That(sent[0].Payload.At, Is.EqualTo(T0.AddMinutes(1)));
    }

    [Test]
    public void Different_subjects_are_different_alerts()
    {
        var driver = new Driver(Setup(Phone));
        driver.Plan(Event(AlertKind.DecoyUsed, "C:\\a.exe"));
        driver.Plan(Event(AlertKind.DecoyUsed, "C:\\b.exe"));
        Assert.That(driver.Sent.Select(d => d.Payload.Key).Distinct().Count(), Is.EqualTo(2));
    }

    [Test]
    public void The_bucket_holds_a_burst_then_counts_and_summarises_when_it_refills()
    {
        var driver = new Driver(Setup(Phone));
        for (var i = 0; i < 8; i++)
            driver.Plan(Event(AlertKind.ProgramBlocked, $"C:\\p{i}.exe"));
        Assert.That(driver.Sent, Has.Count.EqualTo(AlertPlanner.Burst));

        // 10 an hour: one token after six minutes.
        Assert.That(driver.Tick(T0.AddMinutes(5)), Is.Empty);
        var summary = driver.Tick(T0.AddMinutes(6)).Single().Payload;
        Assert.That(summary.Event, Is.EqualTo("alerts.suppressed"));
        Assert.That(summary.Count, Is.EqualTo(3));
        Assert.That(summary.At, Is.EqualTo(T0));
        Assert.That(driver.Tick(T0.AddMinutes(7)), Is.Empty);
    }

    [Test]
    public void The_suppressed_summary_reaches_a_sink_whose_threshold_is_above_warning()
    {
        var driver = new Driver(Setup(Phone));
        for (var i = 0; i < 6; i++)
            driver.Plan(Event(AlertKind.ProgramBlocked, $"C:\\p{i}.exe"));
        Assert.That(driver.Tick(T0.AddHours(1)).Single().Payload.Event, Is.EqualTo("alerts.suppressed"));
    }

    [Test]
    public void A_flood_below_critical_cannot_hide_a_decoy()
    {
        var driver = new Driver(Setup(Phone));
        for (var i = 0; i < 50; i++)
            driver.Plan(Event(AlertKind.ProgramBlocked, $"C:\\p{i}.exe", T0.AddSeconds(i)));

        var decoy = driver.Plan(Event(AlertKind.DecoyUsed, at: T0.AddMinutes(1)));
        Assert.That(decoy.Single().Payload.Event, Is.EqualTo("decoy.used"));
    }

    [Test]
    public void The_critical_bucket_has_its_own_limit()
    {
        var driver = new Driver(Setup(Phone));
        for (var i = 0; i < 15; i++)
            driver.Plan(Event(AlertKind.DecoyUsed, $"C:\\p{i}.exe"));
        Assert.That(driver.Sent, Has.Count.EqualTo(AlertPlanner.CriticalBurst));

        // 30 an hour: a token every two minutes.
        var summary = driver.Tick(T0.AddMinutes(2)).Single().Payload;
        Assert.That((summary.Event, summary.Count), Is.EqualTo(("alerts.suppressed", 5)));
    }

    [Test]
    public void A_storm_collapses_its_source_into_one_alert_per_window()
    {
        var driver = new Driver(Setup(Siem));
        const int total = 300;
        for (var i = 0; i < total; i++)
            driver.Plan(Event(AlertKind.FindingsFailing, $"C:\\p{i}.exe", T0.AddMilliseconds(i * 100)));

        // Past the threshold every new subject joins one window instead of opening its own.
        var windows = driver.State.Sinks["siem"].Windows.Values.ToList();
        Assert.That(windows, Has.Count.EqualTo(AlertPlanner.StormThreshold + 1));
        var storm = windows.Single(w => w.Repeats > 0);
        Assert.That(storm.Repeats, Is.EqualTo(total - AlertPlanner.StormThreshold - 1));
        Assert.That(storm.Detail, Is.Null, "a storm stands for many subjects, so it names none");

        // Long enough for every window to close and every bucket to refill.
        for (var minute = 1; minute <= 180; minute++)
            driver.Tick(T0.AddMinutes(minute));

        // Nothing is lost: every event is in a delivery's count.
        Assert.That(driver.Sent.Sum(d => d.Payload.Count), Is.EqualTo(total));
    }

    [Test]
    public void A_storm_ends_after_a_quiet_minute()
    {
        var driver = new Driver(Setup(Siem));
        for (var i = 0; i <= AlertPlanner.StormThreshold; i++)
            driver.Plan(Event(AlertKind.FindingsFailing, $"C:\\p{i}.exe", T0.AddMilliseconds(i)));
        Assert.That(driver.State.Sinks["siem"].Storms["findings.new"].Storming, Is.True);

        driver.Plan(Event(AlertKind.FindingsFailing, "C:\\late.exe", T0.AddMinutes(3)));
        Assert.That(driver.State.Sinks["siem"].Storms["findings.new"].Storming, Is.False);
    }

    [Test]
    public void A_public_sink_gets_no_detail_and_a_trusted_one_does()
    {
        var plan = AlertPlanner.Plan(Event(AlertKind.DecoyUsed), Setup(Phone, Siem), AlertState.Empty, T0);
        Assert.That(plan.Now.Single(d => d.SinkId == "phone").Payload.Detail, Is.Null);
        Assert.That(plan.Now.Single(d => d.SinkId == "siem").Payload.Detail,
            Is.EqualTo(new TrustedDetail(Program: "C:\\x.exe", ProcessId: 42)));
        Assert.That(Encoding.UTF8.GetString(AlertWire.Serialize(plan.Now[0].Payload)), Does.Not.Contain("detail"));
    }

    [Test]
    public void The_payload_takes_title_and_severity_from_the_table_and_the_machine_from_the_setup()
    {
        var payload = AlertPlanner.Plan(Event(AlertKind.DecoyUsed), Setup(Phone), AlertState.Empty, T0).Now.Single().Payload;
        Assert.That((payload.Event, payload.Severity, payload.Title, payload.Machine, payload.At, payload.Count),
            Is.EqualTo(("decoy.used", AlertSeverity.Critical, "Decoy credential used", "workstation", T0, 1)));
    }

    [Test]
    public void The_key_is_stable_per_subject_and_install_and_hides_the_subject()
    {
        var subject = new AlertSubject(Program: "C:\\x.exe");
        var key = AlertPlanner.KeyFor("decoy.used", subject, InstallKey);
        Assert.That(key, Does.Match("^decoy\\.used:[0-9a-f]{16}$"));
        Assert.That(AlertPlanner.KeyFor("decoy.used", subject with { }, InstallKey), Is.EqualTo(key));
        Assert.That(AlertPlanner.KeyFor("decoy.used", new(Program: "C:\\y.exe"), InstallKey), Is.Not.EqualTo(key));
        Assert.That(AlertPlanner.KeyFor("decoy.used", subject, [.. InstallKey.Reverse()]), Is.Not.EqualTo(key));

        // Fields don't run into each other: a name split differently is a different subject.
        Assert.That(AlertPlanner.KeyFor("x", new(Names: ["ab", "c"]), InstallKey),
            Is.Not.EqualTo(AlertPlanner.KeyFor("x", new(Names: ["a", "bc"]), InstallKey)));
    }

    [Test]
    public void Ids_are_ulids_unique_per_delivery()
    {
        var driver = new Driver(Setup(Phone, Siem));
        for (var i = 0; i < 4; i++)
            driver.Plan(Event(AlertKind.DecoyUsed, $"C:\\p{i}.exe"));
        var ids = driver.Sent.Select(d => d.Payload.Id).ToList();
        Assert.That(ids, Has.All.Match("^[0-9A-HJKMNP-TV-Z]{26}$"));
        Assert.That(ids, Is.Unique);
        Assert.That(ids[0], Does.StartWith("01"), "48 bits of milliseconds from 2026 start with 01");
    }

    [Test]
    public void The_setup_refuses_a_missing_machine_label_a_short_key_and_duplicate_sinks()
    {
        Assert.Throws<ArgumentException>(() => _ = new AlertSetup(" ", InstallKey, []));
        Assert.Throws<ArgumentException>(() => _ = new AlertSetup("workstation", new byte[16], []));
        Assert.Throws<ArgumentException>(() => _ = new AlertSetup("workstation", InstallKey, [Phone, Phone]));
    }

    [Test]
    public void The_event_table_has_one_row_per_event_and_severity()
    {
        Assert.That(AlertKind.All.Select(k => (k.Event, k.Severity)), Is.Unique);
        Assert.That(AlertKind.All.Select(k => k.Event), Has.All.Match("^[a-z]+\\.[a-z-]+$"));
    }

    // ---- Canary: nothing the planner sees leaves a public sink; a trusted one only in detail. ----

    static AlertSubject CanarySubject(ref int n) => new(
        Program: $"C:\\Users\\alice\\CANARY-{n++}\\x.exe",
        ProcessId: 4242,
        Parents: [$"CANARY-{n++}.exe", $"CANARY-{n++}.exe"],
        What: $"CANARY-{n++}",
        Service: $"CANARY-{n++}",
        Names: [$"CANARY-{n++}", $"CANARY-{n++}"],
        Findings: [$"CANARY-{n++}"]);

    static IEnumerable<AlertKind> Kinds => AlertKind.All;

    [TestCaseSource(nameof(Kinds))]
    public void No_canary_reaches_a_public_sink(AlertKind kind)
    {
        var n = 0;
        var subject = CanarySubject(ref n);
        var driver = new Driver(Setup(new SinkDefinition("public", AlertSeverity.Info)));
        // A first occurrence, a repeat for the count summary, and enough distinct ones to hit the suppressed summary.
        driver.Plan(new(kind, subject, T0));
        driver.Plan(new(kind, subject, T0.AddSeconds(1)));
        for (var i = 0; i < 20; i++)
            driver.Plan(new(kind, CanarySubject(ref n), T0.AddSeconds(2 + i)));
        driver.Tick(T0.AddHours(2));

        Assert.That(driver.Sent.Select(d => d.Payload.Count).Max(), Is.GreaterThan(1), "the summaries must be exercised too");
        foreach (var delivery in driver.Sent)
        {
            var json = Encoding.UTF8.GetString(AlertWire.Serialize(delivery.Payload));
            Assert.That(json, Does.Not.Contain("CANARY").And.Not.Contain("alice").And.Not.Contain("4242"));
        }
    }

    [TestCaseSource(nameof(Kinds))]
    public void A_canary_reaches_a_trusted_sink_only_inside_detail(AlertKind kind)
    {
        var n = 0;
        var driver = new Driver(Setup(new SinkDefinition("trusted", AlertSeverity.Info, AlertRedaction.Trusted)));
        driver.Plan(new(kind, CanarySubject(ref n), T0));

        var json = JsonNode.Parse(AlertWire.Serialize(driver.Sent.Single().Payload))!.AsObject();
        var detail = json["detail"]!.ToJsonString();
        Assert.That(Regex.Matches(detail, "CANARY-\\d+").Select(m => m.Value).Distinct().Count(), Is.EqualTo(n),
            "every name and path is in detail");
        json.Remove("detail");
        Assert.That(json.ToJsonString(), Does.Not.Contain("CANARY").And.Not.Contain("alice"));
    }
}
