using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>
/// The app's alerting, sources to sinks (docs/alerts.md): events go through <see cref="AlertPlanner"/>
/// into the <see cref="AlertSender"/>, or to the <see cref="LcdHubLink"/> for an LcdHub sink. Until the first <see cref="Use"/> (the first unlock opens
/// <c>alerts.json</c>) events wait here; after that the configuration stays in memory, locked or not,
/// until the app exits. Watches the sender for failing sinks (<see cref="SinkHealth"/>): each one that
/// starts failing is an <c>alerts.failing</c> to the other sinks, and <see cref="Failing"/> is what
/// Home shows.
/// </summary>
public sealed class AlertCenter : IAsyncDisposable
{
    /// <summary>Events kept while <c>alerts.json</c> isn't open yet; past this the oldest go.</summary>
    public const int MaxWaiting = 100;

    static readonly TimeSpan TickEvery = TimeSpan.FromMinutes(1);

    /// <summary>How long <b>Send a test alert</b> waits for an LcdHub to take the item.</summary>
    static readonly TimeSpan HubTestWait = TimeSpan.FromSeconds(3);

    readonly HttpAlertTransport transport;
    readonly LcdHubLink? hub;
    readonly TimeProvider time;
    readonly Lock gate = new();
    readonly Queue<AlertEvent> waiting = new();
    ITimer? ticker;
    AlertsConfig? config;
    AlertSetup? setup;
    AlertState state = AlertState.Empty;
    IReadOnlyList<FailingSink> failing = [];
    bool opened;

    /// <param name="hub">Where LcdHub sinks show; <c>null</c> drops their deliveries.</param>
    public AlertCenter(HttpAlertTransport transport, TimeProvider time, Action<string> log, LcdHubLink? hub = null)
    {
        this.transport = transport;
        this.hub = hub;
        this.time = time;
        Sender = new AlertSender(transport, time, log);
        Sender.HealthChanged += () => Notify(CheckHealth);
    }

    public AlertSender Sender { get; }

    /// <summary>The configuration in use; <c>null</c> before the first unlock or when alerts aren't set up.</summary>
    public AlertsConfig? Config
    {
        get
        {
            lock (gate)
                return config;
        }
    }

    /// <summary>The sinks whose alerts aren't arriving, muted ones left out: Home's finding.</summary>
    public IReadOnlyList<FailingSink> Failing
    {
        get
        {
            lock (gate)
                return failing;
        }
    }

    /// <summary>Raised, outside any lock and on no particular thread, when <see cref="Failing"/> changed.</summary>
    public event Action? FailingChanged;

    public void Start()
    {
        Sender.Start();
        ticker ??= time.CreateTimer(_ => Tick(), null, TickEvery, TickEvery);
    }

    /// <summary>The configuration just opened or saved, narrowed by <c>app.json</c>; plans what waited for it.</summary>
    public void Use(AlertsConfig? current, IReadOnlyDictionary<string, SinkNarrowing>? narrowing) => Notify(() =>
    {
        lock (gate)
        {
            config = current;
            setup = current?.Setup(narrowing);
            opened = true;
            var live = current?.Live(narrowing) ?? [];
            // A muted sink leaves the sender, and what waits for it (a backlog held while it failed) goes with it.
            Sender.Configure(live.Where(s => s is not LcdHubSink && narrowing?.GetValueOrDefault(s.Id)?.Muted != true));
            if (!live.Any(s => s is LcdHubSink))
                hub?.ClearAll();
            while (waiting.TryDequeue(out var e))
                Plan(e);
            // The first heartbeat goes at unlock, not a minute later.
            if (setup is not null)
                Send(AlertPlanner.Tick(setup, state, time.GetUtcNow()));
            return CheckHealth();
        }
    });

    public void Raise(AlertEvent e)
    {
        lock (gate)
        {
            if (opened)
            {
                Plan(e);
                return;
            }
            if (waiting.Count == MaxWaiting)
                waiting.Dequeue();
            waiting.Enqueue(e);
        }
    }

    /// <summary>
    /// <b>Send a test alert</b>: an <c>alerts.test</c> to <paramref name="sinkId"/> alone, now, outside
    /// dedupe and rate limits (a second test after fixing the receiver must not be deduped away), but
    /// built by the planner like any other. One attempt, no retry: the user waits for the answer.
    /// </summary>
    /// <returns><c>null</c> when no such sink is configured.</returns>
    public async Task<DeliveryResult?> SendTestAsync(string sinkId, CancellationToken ct)
    {
        var current = Config;
        if (current?.Sinks.FirstOrDefault(s => s.Id == sinkId) is not { } sink)
            return null;
        var only = new AlertSetup(current.Machine, current.InstallKey, [new SinkDefinition(sink.Id, AlertSeverity.Info, sink.Redaction)]);
        var now = time.GetUtcNow();
        var plan = AlertPlanner.Plan(new(AlertKind.AlertsTest, AlertSubject.None, now), only, AlertState.Empty, now);
        var payload = plan.Now.Single().Payload;
        if (sink is LcdHubSink)
            return hub is not null && await hub.ShowAndWaitAsync(payload, HubTestWait, ct)
                ? new(DeliveryStatus.Delivered)
                : new(DeliveryStatus.Retry, Error: NoHub);
        var result = await transport.DeliverAsync(payload, sink, ct);
        if (result.Status == DeliveryStatus.Delivered)
            Sender.Resume(sinkId);
        return result;
    }

    /// <summary><see cref="DeliveryResult.Error"/> when no LcdHub took a test alert.</summary>
    public const string NoHub = "NoHub";

    /// <summary>Home showed the findings: the user is back, so the LcdHub's "while you were away" items go.</summary>
    public void FindingsShown() => hub?.ClearAll();

    /// <summary>Releases what time alone sends: dedupe <c>count</c> summaries, <c>alerts.suppressed</c> and heartbeats.</summary>
    public void Tick() => Notify(() =>
    {
        lock (gate)
        {
            if (setup is not null)
                Send(AlertPlanner.Tick(setup, state, time.GetUtcNow()));
            return CheckHealth();
        }
    });

    /// <summary>
    /// Takes the sender's failing sinks as <see cref="Failing"/>, and sends <c>alerts.failing</c> about each
    /// that wasn't failing before. A removed sink has no queue and a fixed one starts again, so both clear.
    /// </summary>
    /// <returns>Whether <see cref="Failing"/> changed.</returns>
    bool CheckHealth()
    {
        lock (gate)
        {
            var muted = setup?.Sinks.Where(s => s.Muted).Select(s => s.Id).ToHashSet(StringComparer.Ordinal) ?? [];
            var current = Sender.Failing().Where(f => !muted.Contains(f.Id)).ToList();
            foreach (var sink in SinkHealth.NewlyFailing(failing, current))
                Plan(AlertSources.AlertsFailing(sink, time.GetUtcNow()));
            var changed = !current.SequenceEqual(failing);
            failing = current;
            return changed;
        }
    }

    /// <summary>Runs <paramref name="change"/>, then raises <see cref="FailingChanged"/> outside the lock if it says so.</summary>
    void Notify(Func<bool> change)
    {
        if (change())
            FailingChanged?.Invoke();
    }

    void Plan(AlertEvent e)
    {
        if (setup is not null)
            Send(AlertPlanner.Plan(e, setup, state, time.GetUtcNow()));
    }

    void Send(AlertPlan plan)
    {
        state = plan.Next;
        foreach (var delivery in plan.Now)
        {
            if (config?.Sinks.FirstOrDefault(s => s.Id == delivery.SinkId) is LcdHubSink)
                hub?.Show(delivery.Payload);
            else
                Sender.Enqueue(delivery);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (ticker is not null)
            await ticker.DisposeAsync();
        await Sender.DisposeAsync();
        if (hub is not null)
            await hub.DisposeAsync();
    }
}
