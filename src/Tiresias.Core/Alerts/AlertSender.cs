using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>When to try a delivery again, and when to give it up (docs/alerts.md, <i>Delivery</i>). Pure.</summary>
public static class DeliveryPolicy
{
    public static readonly TimeSpan FirstRetry = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan GiveUpAfter = TimeSpan.FromHours(24);

    /// <summary>After the <paramref name="failures"/>th failure: 30 s, then 1, 2, 4… minutes, at most 30.</summary>
    public static TimeSpan Backoff(int failures) =>
        failures <= 1 ? FirstRetry : TimeSpan.FromMinutes(Math.Min(MaxBackoff.TotalMinutes, Math.Pow(2, Math.Min(failures - 2, 10))));

    /// <summary>
    /// The next attempt after a <see cref="DeliveryStatus.Retry"/>: no sooner than the receiver's
    /// <c>Retry-After</c>, and no sooner than the backoff, so a receiver answering <c>Retry-After: 0</c>
    /// can't make it spin. Never later than <see cref="GiveUpAfter"/>: the item expires by then anyway, and a
    /// receiver answering <c>Retry-After: 3000000</c> must not put the worker to sleep past what it can wait.
    /// </summary>
    public static DateTimeOffset NextAttempt(DeliveryResult result, int failures, DateTimeOffset now)
    {
        var backoff = Backoff(failures);
        var wait = result.RetryAfter is { } asked && asked > backoff ? asked : backoff;
        return now + (wait < GiveUpAfter ? wait : GiveUpAfter);
    }

    public static bool Expired(DateTimeOffset queuedAt, DateTimeOffset now) => now - queuedAt >= GiveUpAfter;
}

/// <summary>
/// Sends the planner's deliveries: an in-memory queue per sink, drained in order by one worker
/// (docs/alerts.md, <i>Delivery</i>). A failed attempt waits per <see cref="DeliveryPolicy"/>; a
/// <see cref="DeliveryStatus.Stop"/> stops the sink until its target changes or a test gets through.
/// Tracks each sink's <see cref="SinkFailure"/> for <see cref="SinkHealth"/>. Holds only redacted payloads, never written to disk. Logs the sink id, status code and exception
/// type, never the URL, a header or the body.
/// </summary>
public sealed class AlertSender : IAsyncDisposable
{
    sealed record Pending(AlertPayload Payload, DateTimeOffset QueuedAt, int Failures, DateTimeOffset NotBefore);

    sealed class SinkQueue(AlertSink definition)
    {
        public AlertSink Definition = definition;
        public readonly LinkedList<Pending> Items = new();
        public bool Stopped;
        public SinkFailure? Failure;
    }

    readonly HttpAlertTransport transport;
    readonly TimeProvider time;
    readonly Action<string> log;
    readonly Lock gate = new();
    readonly Dictionary<string, SinkQueue> queues = new(StringComparer.Ordinal);
    readonly CancellationTokenSource stop = new();
    TaskCompletionSource signal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    Task? running;

    public AlertSender(HttpAlertTransport transport, TimeProvider time, Action<string> log)
    {
        this.transport = transport;
        this.time = time;
        this.log = log;
    }

    /// <summary>Raised, outside any lock, when a sink stops or delivers after failing; the 15-minute mark is the caller's to check.</summary>
    public event Action? HealthChanged;

    public void Start() => running ??= Task.Run(() => RunAsync(stop.Token));

    /// <summary>
    /// The sinks to deliver to. A sink left out loses its queue. A sink whose URL or headers changed
    /// starts again: its definition was the problem, and the user has fixed it.
    /// </summary>
    public void Configure(IEnumerable<AlertSink> sinks)
    {
        lock (gate)
        {
            var wanted = sinks.ToDictionary(s => s.Id, StringComparer.Ordinal);
            foreach (var id in queues.Keys.Where(id => !wanted.ContainsKey(id)).ToList())
                queues.Remove(id);
            foreach (var sink in wanted.Values)
            {
                if (!queues.TryGetValue(sink.Id, out var queue))
                    queues[sink.Id] = new(sink);
                else
                {
                    if (!queue.Definition.SameTarget(sink))
                        Restart(queue);
                    queue.Definition = sink;
                }
            }
            Wake();
        }
    }

    /// <summary>Queues <paramref name="delivery"/>; one for a sink that isn't configured is dropped.</summary>
    public void Enqueue(Delivery delivery)
    {
        lock (gate)
        {
            if (!queues.TryGetValue(delivery.SinkId, out var queue))
                return;
            var now = time.GetUtcNow();
            queue.Items.AddLast(new Pending(delivery.Payload, now, 0, now));
            Wake();
        }
    }

    public bool IsStopped(string sinkId)
    {
        lock (gate)
            return queues.TryGetValue(sinkId, out var queue) && queue.Stopped;
    }

    /// <summary>
    /// A test alert got through: whatever stopped the sink or failed it is fixed, so what waited goes
    /// now and the sink no longer counts as failing.
    /// </summary>
    public void Resume(string sinkId)
    {
        lock (gate)
        {
            if (!queues.TryGetValue(sinkId, out var queue) || (!queue.Stopped && queue.Failure is null))
                return;
            Restart(queue);
            log($"alerts: sink {sinkId} resumed");
            Wake();
        }
        HealthChanged?.Invoke();
    }

    /// <summary>The sinks failing now, per <see cref="SinkHealth.IsFailing"/>.</summary>
    public IReadOnlyList<FailingSink> Failing()
    {
        var now = time.GetUtcNow();
        lock (gate)
            return [.. queues.Where(q => SinkHealth.IsFailing(q.Value.Failure, now)).Select(q => new FailingSink(q.Key, q.Value.Failure!.Stopped)).OrderBy(f => f.Id, StringComparer.Ordinal)];
    }

    /// <summary>How many deliveries wait for <paramref name="sinkId"/>.</summary>
    public int Waiting(string sinkId)
    {
        lock (gate)
            return queues.TryGetValue(sinkId, out var queue) ? queue.Items.Count : 0;
    }

    void Restart(SinkQueue queue)
    {
        queue.Stopped = false;
        queue.Failure = null;
        if (queue.Items.First is { } head)
            head.Value = head.Value with { Failures = 0, NotBefore = time.GetUtcNow() };
    }

    void Wake() => signal.TrySetResult();

    async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Task wake;
            SinkQueue? due = null;
            Pending? item = null;
            AlertSink? definition = null;
            TimeSpan? wait = null;
            lock (gate)
            {
                if (signal.Task.IsCompleted)
                    signal = new(TaskCreationOptions.RunContinuationsAsynchronously);
                wake = signal.Task;
                var now = time.GetUtcNow();
                foreach (var (id, queue) in queues)
                {
                    while (queue.Items.First?.Value is { } head && DeliveryPolicy.Expired(head.QueuedAt, now))
                    {
                        queue.Items.RemoveFirst();
                        log($"alerts: sink {id} dropped {head.Payload.Event} after {DeliveryPolicy.GiveUpAfter.TotalHours:0} hours undelivered");
                    }
                    if (queue.Stopped || queue.Items.First?.Value is not { } next)
                        continue;
                    if (next.NotBefore <= now)
                    {
                        if (item is null || next.NotBefore < item.NotBefore)
                            (due, item, definition) = (queue, next, queue.Definition);
                    }
                    else if (wait is null || next.NotBefore - now < wait)
                        wait = next.NotBefore - now;
                }
                // A stopped sink still drops what is too old.
                foreach (var queue in queues.Values.Where(q => q.Stopped && q.Items.Count > 0))
                {
                    var untilOldest = queue.Items.First!.Value.QueuedAt + DeliveryPolicy.GiveUpAfter - now;
                    if (wait is null || untilOldest < wait)
                        wait = untilOldest;
                }
            }

            if (due is not null)
            {
                var result = await transport.DeliverAsync(item!.Payload, definition!, ct);
                bool changed;
                lock (gate)
                    changed = Apply(due, item, definition!, result);
                if (changed)
                    HealthChanged?.Invoke();
                continue;
            }

            using var waiting = CancellationTokenSource.CreateLinkedTokenSource(ct);
            try
            {
                await Task.WhenAny(wake, Task.Delay(wait ?? System.Threading.Timeout.InfiniteTimeSpan, time, waiting.Token));
            }
            finally
            {
                await waiting.CancelAsync();
            }
        }
    }

    /// <summary>Applies one attempt's result, unless the sink was removed or retargeted meanwhile.</summary>
    /// <returns>Whether the sink stopped, or delivered after failing.</returns>
    bool Apply(SinkQueue queue, Pending item, AlertSink definition, DeliveryResult result)
    {
        if (!queues.TryGetValue(definition.Id, out var current) || current != queue || queue.Items.First is not { } head || head.Value != item)
            return false;
        var before = queue.Failure;
        queue.Failure = SinkHealth.After(before, result.Status, time.GetUtcNow());
        switch (result.Status)
        {
            case DeliveryStatus.Delivered:
                queue.Items.RemoveFirst();
                break;
            case DeliveryStatus.Stop:
                if (queue.Definition.SameTarget(definition))
                {
                    queue.Stopped = true;
                    log($"alerts: sink {definition.Id} stopped: {result}");
                }
                break;
            default:
                var now = time.GetUtcNow();
                var failures = item.Failures + 1;
                head.Value = item with { Failures = failures, NotBefore = DeliveryPolicy.NextAttempt(result, failures, now) };
                log($"alerts: sink {definition.Id} failed: {result}, attempt {failures}");
                break;
        }
        return before is not null && queue.Failure is null || before?.Stopped != true && queue.Failure?.Stopped == true;
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        if (running is not null)
        {
            try
            {
                await running;
            }
            catch (OperationCanceledException)
            {
            }
        }
        stop.Dispose();
    }
}
