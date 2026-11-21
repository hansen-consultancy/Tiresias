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

    /// <summary>
    /// A stand-in for LcdHub on a pipe of its own: reads the hello, answers with an empty Panels message
    /// (so the link has something to skip), and records every status item and every byte it gets.
    /// </summary>
    internal sealed class FakeHub : IAsyncDisposable
    {
        public sealed record Status(string Key, string Text, LcdHubLevel Level, uint LifetimeMs);

        readonly NamedPipeServerStream server;
        readonly CancellationTokenSource stop = new();
        readonly Lock gate = new();
        readonly MemoryStream raw = new();
        readonly ConcurrentQueue<Status> statuses = new();
        readonly TaskCompletionSource closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly Task serving;

        FakeHub(string pipeName)
        {
            PipeName = pipeName;
            server = new(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.CurrentUserOnly | PipeOptions.Asynchronous);
            serving = ServeAsync();
        }

        public static string NewPipeName() => $"tiresias-test-lcdhub-{Guid.NewGuid():N}";

        public static FakeHub Start(string? pipeName = null) => new(pipeName ?? NewPipeName());

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
                        await server.WriteAsync(Message(2, [0, 0]), stop.Token);
                    }
                    else if (head[4] == 6)
                        statuses.Enqueue(ParseStatus(body));
                }
            }
            catch (Exception e) when (e is OperationCanceledException or IOException or ObjectDisposedException)
            {
            }
            closed.TrySetResult();
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
