using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.RegularExpressions;
using NSec.Cryptography;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Decoys;
using Tiresias.Protocol;
using Tiresias.Vault;

namespace Tiresias.Tests;

/// <summary>
/// The LcdHub sink (docs/alerts.md, phase 4): formatter, wire bytes, the canary, clearing and a missing
/// hub. A fake hub on a pipe name of its own; never the real <c>LcdHub</c> pipe.
/// </summary>
public class AlertLcdHubTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    static AlertPayload Payload(string alertEvent = "decoy.used", AlertSeverity severity = AlertSeverity.Critical, int count = 1,
        string title = "Decoy credential used", TrustedDetail? detail = null) =>
        new("01JD2K8Q4X9V7M3N5P6R8S0T2W", alertEvent, severity, title, "workstation", T0, count, alertEvent + ":5e1f0c9a2b7d4e86", detail);

    static AlertsConfig Config(params AlertSink[] sinks) => new("workstation", InstallKey, sinks);

    static async Task Until(Func<bool> condition, Action? meanwhile = null)
    {
        for (var i = 0; i < 1000 && !condition(); i++)
        {
            meanwhile?.Invoke();
            await Task.Delay(10);
        }
        Assert.That(condition(), Is.True, "timed out");
    }

    // ---- Formatter ----

    [TestCase(AlertSeverity.Info, LcdHubLevel.Info)]
    [TestCase(AlertSeverity.Warning, LcdHubLevel.Warn)]
    [TestCase(AlertSeverity.High, LcdHubLevel.Bad)]
    [TestCase(AlertSeverity.Critical, LcdHubLevel.Bad)]
    public void Severity_maps_to_a_status_level(AlertSeverity severity, LcdHubLevel level) =>
        Assert.That(LcdHubFormat.Level(severity), Is.EqualTo(level));

    [Test]
    public void An_item_is_keyed_by_event_and_shows_the_title_and_count()
    {
        var item = LcdHubFormat.Merge(null, Payload(count: 3), T0, LcdHubFormat.Lifetime);
        Assert.That((item.Key, item.Text, item.Level, item.Until), Is.EqualTo(("tiresias:decoy.used", "Decoy credential used ×3", LcdHubLevel.Bad, T0.AddHours(24))));
    }

    [Test]
    public void Repeats_add_up_keep_the_worst_level_and_renew()
    {
        var first = LcdHubFormat.Merge(null, Payload("findings.new", AlertSeverity.Warning, 1, "New findings"), T0, LcdHubFormat.Lifetime);
        var second = LcdHubFormat.Merge(first, Payload("findings.new", AlertSeverity.Info, 4, "New findings"), T0.AddHours(1), LcdHubFormat.Lifetime);
        Assert.That((second.Text, second.Level, second.Until), Is.EqualTo(("New findings ×5", LcdHubLevel.Warn, T0.AddHours(25))));

        var afterExpiry = LcdHubFormat.Merge(first, Payload("findings.new", AlertSeverity.Info, 2, "New findings"), T0.AddHours(24), LcdHubFormat.Lifetime);
        Assert.That((afterExpiry.Text, afterExpiry.Level), Is.EqualTo(("New findings ×2", LcdHubLevel.Info)), "an expired item starts again");
    }

    [Test]
    public void A_trusted_payload_shows_no_more_than_a_public_one()
    {
        var detail = new TrustedDetail("C:\\Users\\alice\\x.exe", 4242, ["y.exe"], "the decoy admin token", "svc", ["NAME"], ["finding"]);
        Assert.That(LcdHubFormat.Merge(null, Payload(detail: detail), T0, LcdHubFormat.Lifetime),
            Is.EqualTo(LcdHubFormat.Merge(null, Payload(), T0, LcdHubFormat.Lifetime)));
    }

    // ---- Wire v4 ----

    [Test]
    public void Hello_and_status_are_lcdhub_wire_v4_bytes()
    {
        Assert.That(Convert.ToHexStringLower(LcdHubWire.Hello("Tiresias")), Is.EqualTo("0d00000001040008005469726573696173"));
        Assert.That(Convert.ToHexStringLower(LcdHubWire.Status("tiresias:decoy.used", "Decoy credential used ×1", LcdHubLevel.Bad, 86_400_000)),
            Is.EqualTo("3700000006130074697265736961733a6465636f792e7573656419004465636f792063726564656e7469616c207573656420c397310202005c2605"));
        Assert.That(Convert.ToHexStringLower(LcdHubWire.Status("k", "", LcdHubLevel.Info, 0)), Is.EqualTo("080000000601006b00000000"), "empty text withdraws, no lifetime");
    }

    [Test]
    public async Task What_the_hub_sends_is_skipped_and_a_bad_length_is_refused()
    {
        using var stream = new MemoryStream([.. FakeHub.Message(2, [0, 0]), .. FakeHub.Message(99, [1, 2, 3])]);
        Assert.That(await LcdHubWire.SkipAsync(stream, CancellationToken.None), Is.True);
        Assert.That(await LcdHubWire.SkipAsync(stream, CancellationToken.None), Is.True);
        Assert.That(await LcdHubWire.SkipAsync(stream, CancellationToken.None), Is.False);
        Assert.ThrowsAsync<IOException>(() => LcdHubWire.SkipAsync(new MemoryStream([0xff, 0xff, 0xff, 0x7f, 2]), CancellationToken.None));
        Assert.ThrowsAsync<IOException>(() => LcdHubWire.SkipAsync(new MemoryStream([9, 0, 0, 0, 2, 1]), CancellationToken.None));
    }

    // ---- The link, against a fake hub ----

    [Test]
    public async Task An_alert_reaches_the_hub_as_a_status_item()
    {
        await using var hub = FakeHub.Start();
        var log = new ConcurrentQueue<string>();
        await using var link = new LcdHubLink(TimeProvider.System, log.Enqueue, hub.PipeName);

        link.Show(Payload());
        await Until(() => hub.Statuses.Count == 1);

        Assert.That(hub.Hello, Is.EqualTo((LcdHubWire.Version, LcdHubLink.ProducerName)));
        var status = hub.Statuses.Single();
        Assert.That((status.Key, status.Text, status.Level), Is.EqualTo(("tiresias:decoy.used", "Decoy credential used ×1", LcdHubLevel.Bad)));
        Assert.That(status.LifetimeMs, Is.InRange(86_000_000u, 86_400_000u));
        Assert.That(link.Connected, Is.True);
    }

    [Test]
    public async Task With_no_hub_nothing_fails_and_items_wait_for_one()
    {
        var time = new SteppedTime(T0);
        var log = new ConcurrentQueue<string>();
        var pipeName = FakeHub.NewPipeName();
        await using var link = new LcdHubLink(time, log.Enqueue, pipeName);

        link.Show(Payload());
        await Until(() => time.Pending > 0);
        Assert.That((link.Connected, link.Items.Count), Is.EqualTo((false, 1)));
        Assert.That(log, Has.Exactly(1).Contains("no LcdHub").And.All.Not.Contains(pipeName));

        await using var hub = FakeHub.Start(pipeName);
        await Until(() => hub.Statuses.Count == 1, () => time.Advance(LcdHubLink.RetryEvery));
        Assert.That(hub.Statuses.Single().Text, Is.EqualTo("Decoy credential used ×1"));
    }

    [Test]
    public async Task Clearing_withdraws_every_item_and_leaves_the_hub()
    {
        await using var hub = FakeHub.Start();
        await using var link = new LcdHubLink(TimeProvider.System, _ => { }, hub.PipeName);
        link.Show(Payload());
        link.Show(Payload("program.blocked", AlertSeverity.High, 1, "Blocked program asked again"));
        await Until(() => hub.Statuses.Select(s => s.Key).Distinct().Count() == 2);

        link.ClearAll();

        await hub.Closed.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(hub.Statuses.Where(s => s.Text.Length == 0).Select(s => s.Key),
            Is.EquivalentTo(new[] { "tiresias:decoy.used", "tiresias:program.blocked" }));
        Assert.That(link.Items, Is.Empty);
    }

    [Test]
    public async Task A_restarted_hub_gets_the_items_again()
    {
        var time = new SteppedTime(T0);
        var pipeName = FakeHub.NewPipeName();
        await using var link = new LcdHubLink(time, _ => { }, pipeName);
        await using (var first = FakeHub.Start(pipeName))
        {
            link.Show(Payload());
            await Until(() => first.Statuses.Count == 1);
        }

        await using var second = FakeHub.Start(pipeName);
        await Until(() => second.Statuses.Count == 1, () => time.Advance(LcdHubLink.RetryEvery));
        Assert.That(second.Statuses.Single().Key, Is.EqualTo("tiresias:decoy.used"));
    }

    // ---- Through the center ----

    [TestCase(AlertRedaction.Public)]
    [TestCase(AlertRedaction.Trusted)]
    public async Task No_canary_reaches_the_hub_public_or_trusted(AlertRedaction redaction)
    {
        const string Value = "CANARY-value";
        const string Placeholder = "CANARY-placeholder";
        var hit = new DecoyHit(DecoyUse.AdminToken, $"http://127.0.0.1:5999/admin?token={Value}&placeholder={Placeholder}", 4242,
            "C:\\Users\\alice\\CANARY-1\\CANARY-5.exe", T0);
        var alert = AlertSources.DecoyUsed(hit, ["CANARY-2.exe (7)", "CANARY-3.exe (8)"], "CANARY-4")!;

        await using var hub = FakeHub.Start();
        var log = new ConcurrentQueue<string>();
        var time = TimeProvider.System;
        await using var center = new AlertCenter(new HttpAlertTransport(), time, log.Enqueue, new LcdHubLink(time, log.Enqueue, hub.PipeName));
        center.Use(Config(new LcdHubSink("desk", Redaction: redaction)), null);
        center.Raise(alert);
        await Until(() => hub.Statuses.Count == 1);

        var wire = Encoding.UTF8.GetString(hub.Raw);
        Assert.That(wire, Does.Not.Contain("CANARY").And.Not.Contain("alice").And.Not.Contain("4242").And.Not.Contain("workstation"));
        Assert.That(log, Has.All.Not.Contains("CANARY"));
        Assert.That(hub.Statuses.Single().Text, Is.EqualTo("Decoy credential used ×1"));
    }

    [Test]
    public async Task Home_showing_the_findings_clears_the_hub()
    {
        await using var hub = FakeHub.Start();
        var time = TimeProvider.System;
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, new LcdHubLink(time, _ => { }, hub.PipeName));
        center.Use(Config(new LcdHubSink("desk")), null);
        center.Raise(new(AlertKind.DecoyUsed, AlertSubject.None, T0));
        await Until(() => hub.Statuses.Count == 1);

        center.FindingsShown();

        await hub.Closed.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(hub.Statuses[^1], Is.EqualTo(new FakeHub.Status("tiresias:decoy.used", "", LcdHubLevel.Info, 0)));
    }

    [Test]
    public async Task Below_the_threshold_or_muted_nothing_shows()
    {
        await using var hub = FakeHub.Start();
        var time = TimeProvider.System;
        var link = new LcdHubLink(time, _ => { }, hub.PipeName);
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, link);
        center.Use(Config(new LcdHubSink("desk", AlertSeverity.High)), null);
        center.Raise(new(AlertKind.AlertsTest, AlertSubject.None, T0));
        center.Use(Config(new LcdHubSink("desk")), new Dictionary<string, SinkNarrowing> { ["desk"] = new(Muted: true) });
        center.Raise(new(AlertKind.DecoyUsed, AlertSubject.None, T0));

        Assert.That(link.Items, Is.Empty);
    }

    [Test]
    public async Task Removing_the_sink_clears_the_hub()
    {
        await using var hub = FakeHub.Start();
        var time = TimeProvider.System;
        var link = new LcdHubLink(time, _ => { }, hub.PipeName);
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, link);
        center.Use(Config(new LcdHubSink("desk")), null);
        center.Raise(new(AlertKind.DecoyUsed, AlertSubject.None, T0));
        await Until(() => hub.Statuses.Count == 1);

        center.Use(Config(new LcdHubSink("desk")), new Dictionary<string, SinkNarrowing> { ["desk"] = new(Removed: true) });

        await hub.Closed.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(link.Items, Is.Empty);
    }

    [Test]
    public async Task A_test_alert_reaches_the_hub_for_a_minute()
    {
        await using var hub = FakeHub.Start();
        var time = TimeProvider.System;
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, new LcdHubLink(time, _ => { }, hub.PipeName));
        center.Use(Config(new LcdHubSink("desk")), null);

        var result = await center.SendTestAsync("desk", CancellationToken.None);

        Assert.That(result!.Status, Is.EqualTo(DeliveryStatus.Delivered));
        var status = hub.Statuses.Single();
        Assert.That((status.Text, status.Level), Is.EqualTo(("Test alert ×1", LcdHubLevel.Info)));
        Assert.That(status.LifetimeMs, Is.InRange(50_000u, 60_000u));
    }

    [Test]
    public async Task A_test_alert_with_no_hub_says_so()
    {
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, new LcdHubLink(time, _ => { }, FakeHub.NewPipeName()));
        center.Use(Config(new LcdHubSink("desk")), null);

        var test = center.SendTestAsync("desk", CancellationToken.None);
        await Until(() => test.IsCompleted, () => time.Advance(TimeSpan.FromSeconds(1)));

        Assert.That((await test)!.Error, Is.EqualTo(AlertCenter.NoHub));
        var outcome = AlertsCard.Outcome("desk", await test);
        Assert.That((outcome.Key, outcome.Args), Is.EqualTo(("Alerts_TestNoHub", new object[] { "desk" })));
    }

    [Test]
    public async Task Without_a_link_lcdhub_deliveries_are_dropped_and_http_sinks_never_see_them()
    {
        var handler = FakeHandler.Always(System.Net.HttpStatusCode.OK);
        var time = new SteppedTime(T0);
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, _ => { });
        center.Start();
        center.Use(Config(new LcdHubSink("desk")), null);
        center.Raise(new(AlertKind.DecoyUsed, AlertSubject.None, T0));
        Assert.That(await center.SendTestAsync("desk", CancellationToken.None), Has.Property("Error").EqualTo(AlertCenter.NoHub));
        Assert.That(handler.Requests, Is.Empty);
    }

    // ---- Config and form ----

    [Test]
    public void Round_trips_sealed_beside_other_sinks()
    {
        var hello = X25519KeyWrapper.ForKey("hello", Key.Create(KeyAgreementAlgorithm.X25519));
        var recovery = X25519KeyWrapper.ForKey("recovery", Key.Create(KeyAgreementAlgorithm.X25519));
        var config = Config(new LcdHubSink("desk"), new WebhookSink("siem", new("https://hooks.example.com/t"), []));

        var back = AlertsFile.Open(AlertsFile.Seal(config, 0, hello, recovery), hello).Config!;

        Assert.That(back.Sinks, Is.EqualTo(config.Sinks));
        Assert.That(back.Sinks[0], Is.EqualTo(new LcdHubSink("desk", AlertSeverity.Warning, AlertRedaction.Public)));
        Assert.That(config.ToDocument()["sinks"]![0]!.ToJsonString(), Is.EqualTo("""{"id":"desk","kind":"lcdhub","threshold":"warning","redaction":"public"}"""));
        Assert.That(new LcdHubSink("desk").ToString(), Is.EqualTo("lcdhub desk"));
    }

    [Test]
    public void The_form_takes_an_id_and_a_threshold_and_one_hub_only()
    {
        var (sink, problem) = AlertsCard.BuildLcdHub(true, "workstation", " desk ", AlertSeverity.Warning, []);
        Assert.That((problem, sink), Is.EqualTo(((Phrase?)null, new LcdHubSink("desk"))));
        Assert.That(AlertsCard.BuildLcdHub(true, " ", "desk", AlertSeverity.Warning, []).Problem, Is.EqualTo(new Phrase("Alerts_NeedMachine")));
        Assert.That(AlertsCard.BuildLcdHub(false, "", "Desk!", AlertSeverity.Warning, []).Problem, Is.EqualTo(new Phrase("Alerts_BadId")));
        Assert.That(AlertsCard.BuildLcdHub(false, "", "desk", AlertSeverity.Warning, [new WebhookSink("desk", new("https://example.com"), [])]).Problem!.Key,
            Is.EqualTo("Alerts_IdTaken"));
        Assert.That(AlertsCard.BuildLcdHub(false, "", "other", AlertSeverity.Warning, [new LcdHubSink("desk")]).Problem, Is.EqualTo(new Phrase("Alerts_LcdHubTaken")));
        Assert.That((AlertsCard.HasLcdHub([new LcdHubSink("desk")]), AlertsCard.HasLcdHub(null)), Is.EqualTo((true, false)));
    }

    // ---- The alert frame for critical (docs/alerts.md, LcdHub alert frame) ----

    static readonly LcdHubPanel Wide = new("main", 32, 8);
    static readonly LcdHubPanel Small = new("side", 16, 4);

    /// <summary>A renderer that records what it was asked to draw and paints every pixel one colour.</summary>
    sealed class FakeRenderer
    {
        public readonly ConcurrentQueue<(LcdHubCard Card, int Width, int Height)> Drawn = new();
        public Func<LcdHubCard, int, int, uint[]>? Instead;

        public uint[] Render(LcdHubCard card, int width, int height)
        {
            Drawn.Enqueue((card, width, height));
            return Instead?.Invoke(card, width, height) ?? Enumerable.Repeat(0x007F1D1Du, width * height).ToArray();
        }
    }

    [Test]
    public void Frame_and_panels_are_lcdhub_wire_v4_bytes()
    {
        Assert.That(Convert.ToHexStringLower(LcdHubWire.Frame("p", alert: true, 1000, [0x00112233u])),
            Is.EqualTo("0d0000000301007005e803000033221100"), "id, flags alert|lifetime, lifetime, one BGRX pixel");
        Assert.That(Convert.ToHexStringLower(LcdHubWire.Frame("p", alert: false, 0, [])), Is.EqualTo("0500000003010070" + "00"), "no pixels withdraws");
        Assert.That(LcdHubWire.Panels(FakeHub.PanelsMessage([Wide, Small]).AsSpan(5)), Is.EqualTo(new[] { Wide, Small }));
        Assert.Throws<IOException>(() => LcdHubWire.Panels(new byte[] { 1, 0, 9, 0 }));
    }

    [TestCase(0, 8)]
    [TestCase(32, 0)]
    [TestCase(65535, 65535)]
    [TestCase(4096, 1024)]
    public void A_panel_no_frame_fits_is_refused_like_a_bad_message(int width, int height)
    {
        var lying = FakeHub.PanelsMessage([new LcdHubPanel("main", width, height)])[5..];
        Assert.Throws<IOException>(() => LcdHubWire.Panels(lying));
    }

    [Test]
    public void The_card_shows_the_severity_the_title_and_the_count_only()
    {
        var detail = new TrustedDetail("C:\\Users\\alice\\x.exe", 4242, ["y.exe"], "the decoy admin token", "svc", ["NAME"], ["finding"]);
        var item = LcdHubFormat.Merge(null, Payload(count: 3, detail: detail), T0, LcdHubFormat.Lifetime);
        var card = LcdHubFormat.Card(item, AlertSeverity.Critical);

        Assert.That(card.Lines, Is.EqualTo(new[] { "CRITICAL", "Decoy credential used", "×3 · Open Tiresias" }));
        Assert.That(LcdHubFormat.TakesOver(Payload()), Is.True);
        Assert.That(LcdHubFormat.TakesOver(Payload("program.blocked", AlertSeverity.High)), Is.False);
    }

    [Test]
    public async Task A_critical_alert_takes_every_panel_over_at_its_size()
    {
        await using var hub = FakeHub.Start(null, Wide, Small);
        var renderer = new FakeRenderer();
        await using var link = new LcdHubLink(TimeProvider.System, _ => { }, hub.PipeName, renderer.Render);

        link.Show(Payload("program.blocked", AlertSeverity.High, title: "Blocked program asked again"));
        await Until(() => hub.Statuses.Count == 1);
        await Task.Delay(100);
        Assert.That(hub.Frames, Is.Empty, "below critical: the strip only");

        link.Show(Payload());
        await Until(() => hub.Frames.Count == 2);

        Assert.That(hub.Frames.Select(f => (f.PanelId, f.Alert, f.Pixels)), Is.EquivalentTo(new[] { ("main", true, 32 * 8), ("side", true, 16 * 4) }));
        Assert.That(hub.Frames.Select(f => f.LifetimeMs), Is.All.InRange(86_000_000u, 86_400_000u));
        Assert.That(renderer.Drawn.Select(d => (d.Width, d.Height)), Is.EquivalentTo(new[] { (32, 8), (16, 4) }));
        Assert.That(link.Card!.Lines[1], Is.EqualTo("Decoy credential used"));
    }

    [Test]
    public async Task Home_showing_the_findings_withdraws_the_frame()
    {
        await using var hub = FakeHub.Start(null, Wide);
        await using var link = new LcdHubLink(TimeProvider.System, _ => { }, hub.PipeName, new FakeRenderer().Render);
        link.Show(Payload());
        await Until(() => hub.Frames.Count == 1);

        link.ClearAll();

        await hub.Closed.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(hub.Frames[^1], Is.EqualTo(new FakeHub.Frame("main", false, 0, 0)));
        Assert.That(link.Card, Is.Null);
    }

    [Test]
    public async Task New_panels_get_the_frame_again_at_their_size()
    {
        await using var hub = FakeHub.Start(null, Wide);
        var renderer = new FakeRenderer();
        await using var link = new LcdHubLink(TimeProvider.System, _ => { }, hub.PipeName, renderer.Render);
        link.Show(Payload());
        await Until(() => hub.Frames.Count == 1);

        await hub.AnnounceAsync(Small);

        await Until(() => hub.Frames.Count == 2);
        Assert.That((hub.Frames[1].PanelId, hub.Frames[1].Pixels), Is.EqualTo(("side", 16 * 4)));
    }

    [Test]
    public async Task Without_a_renderer_or_when_it_fails_the_strip_still_shows()
    {
        await using (var hub = FakeHub.Start(null, Wide))
        await using (var link = new LcdHubLink(TimeProvider.System, _ => { }, hub.PipeName))
        {
            link.Show(Payload());
            await Until(() => hub.Statuses.Count == 1);
            await Task.Delay(100);
            Assert.That(hub.Frames, Is.Empty);
        }

        await using var failing = FakeHub.Start(null, Wide);
        var log = new ConcurrentQueue<string>();
        var renderer = new FakeRenderer { Instead = (_, _, _) => throw new InvalidOperationException("CANARY-render") };
        await using var link2 = new LcdHubLink(TimeProvider.System, log.Enqueue, failing.PipeName, renderer.Render);
        link2.Show(Payload());
        await Until(() => failing.Frames.Count == 1);
        Assert.That((failing.Frames[0].Pixels, failing.Statuses.Count), Is.EqualTo((32 * 8, 1)), "a black frame of the right size; the item went too");
        Assert.That(log, Has.Some.Contains(nameof(InvalidOperationException)).And.All.Not.Contains("CANARY"));
    }

    [TestCase(AlertRedaction.Public)]
    [TestCase(AlertRedaction.Trusted)]
    public async Task No_canary_reaches_the_frame_public_or_trusted(AlertRedaction redaction)
    {
        var hit = new DecoyHit(DecoyUse.AdminToken, "http://127.0.0.1:5999/admin?token=CANARY-value&placeholder=CANARY-placeholder", 4242,
            "C:\\Users\\alice\\CANARY-1\\CANARY-5.exe", T0);
        var alert = AlertSources.DecoyUsed(hit, ["CANARY-2.exe (7)", "CANARY-3.exe (8)"], "CANARY-4")!;

        await using var hub = FakeHub.Start(null, Wide);
        var renderer = new FakeRenderer();
        var time = TimeProvider.System;
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, new LcdHubLink(time, _ => { }, hub.PipeName, renderer.Render));
        center.Use(Config(new LcdHubSink("desk", Redaction: redaction)), null);
        center.Raise(alert);
        await Until(() => hub.Frames.Count == 1);

        var drawn = string.Join("\n", renderer.Drawn.SelectMany(d => d.Card.Lines));
        Assert.That(drawn, Is.EqualTo("CRITICAL\nDecoy credential used\n×1 · Open Tiresias"));
        Assert.That(drawn + Encoding.UTF8.GetString(hub.Raw), Does.Not.Contain("CANARY").And.Not.Contain("alice").And.Not.Contain("4242").And.Not.Contain("workstation"));
    }

    [Test]
    public async Task A_critical_frame_comes_back_when_a_test_frame_ends()
    {
        await using var hub = FakeHub.Start(null, Wide);
        var time = new SteppedTime(DateTimeOffset.UtcNow);
        var renderer = new FakeRenderer();
        await using var link = new LcdHubLink(time, _ => { }, hub.PipeName, renderer.Render);
        link.Show(Payload());
        await Until(() => hub.Frames.Count == 1);

        Assert.That(await link.ShowAndWaitAsync(Payload("alerts.test", AlertSeverity.Info, title: "Test alert"), TimeSpan.FromSeconds(10), CancellationToken.None), Is.True);
        await Until(() => hub.Frames.Count == 2 && time.Pending > 0);
        time.Advance(LcdHubFormat.TestLifetime + TimeSpan.FromSeconds(1));

        await Until(() => hub.Frames.Count == 3);
        Assert.That(renderer.Drawn.Select(d => d.Card.Severity), Is.EqualTo(new[] { AlertSeverity.Critical, AlertSeverity.Info, AlertSeverity.Critical }));
        Assert.That(hub.Frames[2].LifetimeMs, Is.InRange(86_000_000u, 86_400_000u), "the rest of the critical item's lifetime");
    }

    [Test]
    public async Task A_test_alert_shows_the_frame_for_its_minute()
    {
        await using var hub = FakeHub.Start(null, Wide);
        var renderer = new FakeRenderer();
        var time = TimeProvider.System;
        await using var center = new AlertCenter(new HttpAlertTransport(), time, _ => { }, new LcdHubLink(time, _ => { }, hub.PipeName, renderer.Render));
        center.Use(Config(new LcdHubSink("desk")), null);

        await center.SendTestAsync("desk", CancellationToken.None);
        await Until(() => hub.Frames.Count == 1);

        Assert.That(hub.Frames[0].LifetimeMs, Is.InRange(50_000u, 60_000u));
        Assert.That(renderer.Drawn.Single().Card, Has.Property("Severity").EqualTo(AlertSeverity.Info));
    }

    /// <summary>
    /// A stand-in for LcdHub on a pipe of its own: reads the hello, answers with an empty Panels message
    /// (so the link has something to skip), and records every status item and every byte it gets.
    /// </summary>
    sealed class FakeHub : IAsyncDisposable
    {
        public sealed record Status(string Key, string Text, LcdHubLevel Level, uint LifetimeMs);

        /// <param name="Pixels">How many pixels came; 0 withdraws.</param>
        public sealed record Frame(string PanelId, bool Alert, uint LifetimeMs, int Pixels);

        readonly LcdHubPanel[] announce;
        readonly ConcurrentQueue<Frame> frames = new();

        readonly NamedPipeServerStream server;
        readonly CancellationTokenSource stop = new();
        readonly Lock gate = new();
        readonly MemoryStream raw = new();
        readonly ConcurrentQueue<Status> statuses = new();
        readonly TaskCompletionSource closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly Task serving;

        FakeHub(string pipeName, LcdHubPanel[] announce)
        {
            PipeName = pipeName;
            this.announce = announce;
            server = new(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.CurrentUserOnly | PipeOptions.Asynchronous);
            serving = ServeAsync();
        }

        public static string NewPipeName() => $"tiresias-test-lcdhub-{Guid.NewGuid():N}";

        public static FakeHub Start(string? pipeName = null, params LcdHubPanel[] panels) => new(pipeName ?? NewPipeName(), panels);

        public IReadOnlyList<Frame> Frames => [.. frames];

        /// <summary>A Panels message, as the hub sends after hello and whenever its panels change.</summary>
        public static byte[] PanelsMessage(IReadOnlyList<LcdHubPanel> panels)
        {
            var body = new List<byte>();
            body.AddRange(BitConverter.GetBytes((ushort)panels.Count));
            foreach (var panel in panels)
            {
                var id = Encoding.UTF8.GetBytes(panel.Id);
                body.AddRange(BitConverter.GetBytes((ushort)id.Length));
                body.AddRange(id);
                body.AddRange(BitConverter.GetBytes((ushort)panel.Width));
                body.AddRange(BitConverter.GetBytes((ushort)panel.Height));
            }
            return Message(2, [.. body]);
        }

        public Task AnnounceAsync(params LcdHubPanel[] panels) => server.WriteAsync(PanelsMessage(panels), stop.Token).AsTask();

        public string PipeName { get; }
        public (ushort Version, string Name)? Hello { get; private set; }
        public IReadOnlyList<Status> Statuses => [.. statuses];
        public Task Closed => closed.Task;

        public byte[] Raw
        {
            get
            {
                lock (gate)
                    return raw.ToArray();
            }
        }

        public static byte[] Message(byte type, byte[] body)
        {
            var message = new byte[5 + body.Length];
            BinaryPrimitives.WriteInt32LittleEndian(message, body.Length + 1);
            message[4] = type;
            body.CopyTo(message, 5);
            return message;
        }

        async Task ServeAsync()
        {
            try
            {
                await server.WaitForConnectionAsync(stop.Token);
                var head = new byte[5];
                while (await server.ReadAtLeastAsync(head, 5, throwOnEndOfStream: false, stop.Token) == 5)
                {
                    var body = new byte[BinaryPrimitives.ReadInt32LittleEndian(head) - 1];
                    await server.ReadExactlyAsync(body, stop.Token);
                    lock (gate)
                    {
                        raw.Write(head);
                        raw.Write(body);
                    }
                    if (head[4] == 1)
                    {
                        var name = Encoding.UTF8.GetString(body, 4, BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(2)));
                        Hello = (BinaryPrimitives.ReadUInt16LittleEndian(body), name);
                        await server.WriteAsync(PanelsMessage(announce), stop.Token);
                    }
                    else if (head[4] == 6)
                        statuses.Enqueue(ParseStatus(body));
                    else if (head[4] == 3)
                        frames.Enqueue(ParseFrame(body));
                }
            }
            catch (Exception e) when (e is OperationCanceledException or IOException or ObjectDisposedException)
            {
            }
            closed.TrySetResult();
        }

        static Frame ParseFrame(byte[] body)
        {
            var n = BinaryPrimitives.ReadUInt16LittleEndian(body);
            var id = Encoding.UTF8.GetString(body, 2, n);
            var at = 2 + n;
            var flags = body[at++];
            var lifetime = 0u;
            if ((flags & 4) != 0)
            {
                lifetime = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at));
                at += 4;
            }
            return new(id, (flags & 1) != 0, lifetime, (body.Length - at) / 4);
        }

        static Status ParseStatus(byte[] body)
        {
            var at = 0;
            string Str()
            {
                var n = BinaryPrimitives.ReadUInt16LittleEndian(body.AsSpan(at));
                var s = Encoding.UTF8.GetString(body, at + 2, n);
                at += 2 + n;
                return s;
            }
            var key = Str();
            var text = Str();
            var level = (LcdHubLevel)body[at++];
            var flags = body[at++];
            var lifetime = (flags & 2) != 0 ? BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(at)) : 0u;
            return new(key, text, level, lifetime);
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            await server.DisposeAsync();
            await serving;
            stop.Dispose();
        }
    }
}
