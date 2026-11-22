using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>Turns what a source reports into an <see cref="AlertEvent"/>: names and paths only, never a value.</summary>
public static class AlertSources
{
    /// <summary>
    /// <c>decoy.used</c> for a decoy credential used; <c>null</c> for a decoy file read, which is
    /// <c>decoy.read</c>'s (a later phase). The endpoint is left out: it can carry what the program sent.
    /// </summary>
    /// <param name="parents">The processes that started it, nearest first.</param>
    /// <param name="what">Which decoy, in the activity log's words (<c>DecoyTouch.What</c>).</param>
    public static AlertEvent? DecoyUsed(DecoyHit hit, IReadOnlyList<string> parents, string what) =>
        hit.Use == DecoyUse.Read ? null
            : new(AlertKind.DecoyUsed, new AlertSubject(Program: hit.Program, ProcessId: hit.ProcessId, Parents: parents, What: what), hit.At);
}

/// <summary>
/// The app's alerting, sources to sinks (docs/alerts.md): events go through <see cref="AlertPlanner"/>
/// into the <see cref="AlertSender"/>. Until the first <see cref="Use"/> (the first unlock opens
/// <c>alerts.json</c>) events wait here; after that the configuration stays in memory, locked or not,
/// until the app exits.
/// </summary>
public sealed class AlertCenter : IAsyncDisposable
{
    /// <summary>Events kept while <c>alerts.json</c> isn't open yet; past this the oldest go.</summary>
    public const int MaxWaiting = 100;

    static readonly TimeSpan TickEvery = TimeSpan.FromMinutes(1);

    readonly HttpAlertTransport transport;
    readonly TimeProvider time;
    readonly Lock gate = new();
    readonly Queue<AlertEvent> waiting = new();
    ITimer? ticker;
    AlertsConfig? config;
    AlertSetup? setup;
    AlertState state = AlertState.Empty;
    bool opened;

    public AlertCenter(HttpAlertTransport transport, TimeProvider time, Action<string> log)
    {
        this.transport = transport;
        this.time = time;
        Sender = new AlertSender(transport, time, log);
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

    public void Start()
    {
        Sender.Start();
        ticker ??= time.CreateTimer(_ => Tick(), null, TickEvery, TickEvery);
    }

    /// <summary>The configuration just opened or saved, narrowed by <c>app.json</c>; plans what waited for it.</summary>
    public void Use(AlertsConfig? current, IReadOnlyDictionary<string, SinkNarrowing>? narrowing)
    {
        lock (gate)
        {
            config = current;
            setup = current?.Setup(narrowing);
            opened = true;
            // A muted sink leaves the sender, and what waits for it (a backlog held while it failed) goes with it.
            Sender.Configure(current?.Live(narrowing).Where(s => narrowing?.GetValueOrDefault(s.Id)?.Muted != true) ?? []);
            while (waiting.TryDequeue(out var e))
                Plan(e);
        }
    }

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
        var result = await transport.DeliverAsync(plan.Now.Single().Payload, sink, ct);
        if (result.Status == DeliveryStatus.Delivered)
            Sender.Resume(sinkId);
        return result;
    }

    /// <summary>Releases what time alone sends: dedupe <c>count</c> summaries and <c>alerts.suppressed</c>.</summary>
    public void Tick()
    {
        lock (gate)
        {
            if (setup is not null)
                Send(AlertPlanner.Tick(setup, state, time.GetUtcNow()));
        }
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
            Sender.Enqueue(delivery);
    }

    public async ValueTask DisposeAsync()
    {
        if (ticker is not null)
            await ticker.DisposeAsync();
        await Sender.DisposeAsync();
    }
}
