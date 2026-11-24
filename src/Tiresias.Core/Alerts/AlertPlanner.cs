using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>Something that happened, as a source reports it. <see cref="Subject"/> never leaves as is.</summary>
public sealed record AlertEvent(AlertKind Kind, AlertSubject Subject, DateTimeOffset At);

/// <summary>
/// What the source knows about an event. Never serialized: the planner hashes it into the payload's
/// <c>key</c> for every sink and copies it into a <see cref="TrustedDetail"/> for trusted sinks only.
/// Names and paths only; a source never puts a value, a token or a command line here.
/// </summary>
/// <param name="Sink">The sink an event is about (<c>alerts.failing</c>): the planner never sends it to that sink,
/// and a trusted sink gets the id as <see cref="TrustedDetail.What"/>. Never its address or credential.</param>
public sealed record AlertSubject(
    string? Program = null,
    int? ProcessId = null,
    IReadOnlyList<string>? Parents = null,
    string? What = null,
    string? Service = null,
    IReadOnlyList<string>? Names = null,
    IReadOnlyList<string>? Findings = null,
    string? Sink = null)
{
    public static readonly AlertSubject None = new();
}

public enum AlertRedaction
{
    /// <summary>Event, severity, title, count, time, machine label and key. The default.</summary>
    Public,
    /// <summary>Also <see cref="TrustedDetail"/>: names and paths, never values.</summary>
    Trusted,
}

/// <summary>What the planner needs to know about a sink; where and how it delivers is the transport's business.</summary>
/// <param name="Heartbeat">How often <see cref="AlertPlanner.Tick"/> sends it an <c>alerts.alive</c>; <c>null</c> for never.</param>
public sealed record SinkDefinition(string Id, AlertSeverity Threshold, AlertRedaction Redaction = AlertRedaction.Public, bool Muted = false,
    TimeSpan? Heartbeat = null);

/// <summary>The alert configuration the planner works from.</summary>
/// <param name="Machine">The label the user chose for this machine; required, never the host name.</param>
/// <param name="InstallKey">A random per-install key: keys the payload's <c>key</c> and its <c>id</c>.</param>
public sealed record AlertSetup
{
    public AlertSetup(string machine, byte[] installKey, IReadOnlyList<SinkDefinition> sinks)
    {
        if (string.IsNullOrWhiteSpace(machine))
            throw new ArgumentException("Alerts need a machine label.", nameof(machine));
        if (installKey.Length < 32)
            throw new ArgumentException("The install key must be at least 32 bytes.", nameof(installKey));
        if (sinks.Select(s => s.Id).Distinct(StringComparer.Ordinal).Count() != sinks.Count)
            throw new ArgumentException("Sink ids must be unique.", nameof(sinks));
        Machine = machine;
        InstallKey = installKey;
        Sinks = sinks;
    }

    public string Machine { get; }
    public byte[] InstallKey { get; }
    public IReadOnlyList<SinkDefinition> Sinks { get; }
}

public sealed record Delivery(string SinkId, AlertPayload Payload);

/// <param name="Now">What to send now, already redacted per sink.</param>
/// <param name="Next">The state to pass to the next call.</param>
public sealed record AlertPlan(IReadOnlyList<Delivery> Now, AlertState Next);

/// <summary>The planner's memory between calls: dedupe windows, rate buckets and storm counters per sink. Opaque to callers.</summary>
public sealed record AlertState
{
    public static AlertState Empty { get; } = new(ImmutableDictionary<string, SinkState>.Empty, 0, ImmutableDictionary<string, DateTimeOffset>.Empty);

    internal AlertState(ImmutableDictionary<string, SinkState> sinks, long sequence, ImmutableDictionary<string, DateTimeOffset> alive)
    {
        Sinks = sinks;
        Sequence = sequence;
        Alive = alive;
    }

    internal ImmutableDictionary<string, SinkState> Sinks { get; init; }

    /// <summary>When each sink last got an <c>alerts.alive</c>.</summary>
    internal ImmutableDictionary<string, DateTimeOffset> Alive { get; init; }

    /// <summary>Counts deliveries, so each gets its own id.</summary>
    internal long Sequence { get; init; }
}

internal sealed record SinkState(
    Bucket Normal,
    Bucket Critical,
    ImmutableDictionary<string, DedupeWindow> Windows,
    ImmutableDictionary<string, StormCounter> Storms);

/// <summary>
/// A token bucket, and how many occurrences it held back since it last ran dry. <see cref="Credit"/> is
/// the time earned towards tokens, so refilling is exact: one token is an hour divided by the rate.
/// </summary>
internal sealed record Bucket(TimeSpan Credit, DateTimeOffset RefilledAt, int Suppressed, DateTimeOffset? FirstSuppressedAt);

/// <summary>One key's dedupe window: the first occurrence went out (or was held back), repeats only count.</summary>
internal sealed record DedupeWindow(DateTimeOffset Opened, AlertKind Kind, string Key, TrustedDetail? Detail, int Repeats, DateTimeOffset? FirstRepeatAt);

/// <summary>Events of one source in the current minute; <see cref="Storming"/> collapses the source into one window.</summary>
internal sealed record StormCounter(DateTimeOffset MinuteStart, int Count, bool Storming);

/// <summary>
/// Decides what each sink gets for an event (docs/alerts.md, <i>The planner</i>): per sink, drop
/// below its threshold, dedupe, rate-limit, redact. Pure: the clock and the state come in, deliveries
/// and the next state go out. Transports only ever see the <see cref="AlertPayload"/> it builds.
/// </summary>
public static class AlertPlanner
{
    public static readonly TimeSpan DedupeWindow = TimeSpan.FromMinutes(10);

    /// <summary>The bucket for everything below critical: 10 an hour, burst 5.</summary>
    public const int Burst = 5;
    public const int PerHour = 10;

    /// <summary>Critical's own bucket, so a flood of findings can't hide a decoy: 30 an hour, burst 10.</summary>
    public const int CriticalBurst = 10;
    public const int CriticalPerHour = 30;

    /// <summary>More events than this from one source within a minute is a storm.</summary>
    public const int StormThreshold = 100;

    static readonly TimeSpan StormMinute = TimeSpan.FromMinutes(1);
    static readonly TimeSpan Cost = TimeSpan.FromHours(1) / PerHour;
    static readonly TimeSpan CriticalCost = TimeSpan.FromHours(1) / CriticalPerHour;

    /// <summary>
    /// Plans <paramref name="e"/> for every sink. Also sends what <see cref="Tick"/> would, so a caller
    /// that ticks rarely loses nothing.
    /// </summary>
    public static AlertPlan Plan(AlertEvent e, AlertSetup setup, AlertState state, DateTimeOffset now)
    {
        var run = new Run(setup, Tick(setup, state, now));
        foreach (var sink in setup.Sinks)
        {
            // An event about a sink goes to the others: the sink itself is the one not delivering. It
            // ignores their thresholds, as alerts.suppressed does: it says alerts may be missing.
            if (sink.Muted || sink.Id == e.Subject.Sink || (e.Kind.Severity < sink.Threshold && e.Kind != AlertKind.AlertsFailing))
                continue;
            run.Event(sink, e, now);
        }
        return run.Result();
    }

    /// <summary>
    /// Sends what time alone releases: the <c>count</c> summary of a dedupe window that closed with
    /// repeats, an <c>alerts.suppressed</c> summary once a bucket that held alerts back refills, and an
    /// <c>alerts.alive</c> to each sink whose heartbeat is due. Call it about once a minute.
    /// </summary>
    public static AlertPlan Tick(AlertSetup setup, AlertState state, DateTimeOffset now)
    {
        var run = new Run(setup, new AlertPlan([], state));
        run.Forget(setup.Sinks.Where(s => !s.Muted).Select(s => s.Id));
        foreach (var sink in setup.Sinks.Where(s => !s.Muted))
        {
            run.Tick(sink, now);
            run.Heartbeat(sink, now);
        }
        return run.Result();
    }

    /// <summary><c>event:</c> plus 16 hex of HMAC-SHA-256 over the subject: stable per subject and install, useless for guessing it.</summary>
    internal static string KeyFor(string eventName, AlertSubject subject, byte[] installKey)
    {
        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            WriteText(writer, subject.Program);
            writer.Write(subject.ProcessId.HasValue);
            writer.Write(subject.ProcessId ?? 0);
            WriteList(writer, subject.Parents);
            WriteText(writer, subject.What);
            WriteText(writer, subject.Service);
            WriteList(writer, subject.Names);
            WriteList(writer, subject.Findings);
            // Written only when set, so the keys of subjects without it stay what they were.
            if (subject.Sink is not null)
                WriteText(writer, subject.Sink);
        }
        var mac = HMACSHA256.HashData(installKey, buffer.ToArray());
        return $"{eventName}:{Convert.ToHexStringLower(mac.AsSpan(0, 8))}";

        static void WriteText(BinaryWriter writer, string? text)
        {
            writer.Write(text is not null);
            writer.Write(text ?? "");
        }

        static void WriteList(BinaryWriter writer, IReadOnlyList<string>? list)
        {
            writer.Write(list?.Count ?? -1);
            foreach (var item in list ?? [])
                writer.Write(item);
        }
    }

    static TrustedDetail? DetailFor(AlertSubject s)
    {
        var detail = new TrustedDetail(s.Program, s.ProcessId, NullIfEmpty(s.Parents), s.What ?? s.Sink, s.Service, NullIfEmpty(s.Names), NullIfEmpty(s.Findings));
        return detail == new TrustedDetail() ? null : detail;

        static IReadOnlyList<string>? NullIfEmpty(IReadOnlyList<string>? list) => list is { Count: > 0 } ? [.. list] : null;
    }

    /// <summary>One planner call's working copy of the state, and the deliveries it has made so far.</summary>
    sealed class Run(AlertSetup setup, AlertPlan start)
    {
        readonly List<Delivery> deliveries = [.. start.Now];
        ImmutableDictionary<string, SinkState> sinks = start.Next.Sinks;
        ImmutableDictionary<string, DateTimeOffset> alive = start.Next.Alive;
        long sequence = start.Next.Sequence;

        public AlertPlan Result() => new(deliveries, new AlertState(sinks, sequence, alive));

        /// <summary>A removed or muted sink keeps nothing, so unmuting it doesn't replay old summaries.</summary>
        public void Forget(IEnumerable<string> keep)
        {
            var kept = keep.ToHashSet(StringComparer.Ordinal);
            foreach (var id in sinks.Keys.Where(id => !kept.Contains(id)).ToList())
                sinks = sinks.Remove(id);
            foreach (var id in alive.Keys.Where(id => !kept.Contains(id)).ToList())
                alive = alive.Remove(id);
        }

        /// <summary>
        /// An <c>alerts.alive</c> once the sink's heartbeat is due, the first at once. Outside threshold,
        /// dedupe and buckets: a receiver counts on it arriving. Public on every sink: the label and the time.
        /// </summary>
        public void Heartbeat(SinkDefinition sink, DateTimeOffset now)
        {
            if (sink.Heartbeat is not { } every || (alive.TryGetValue(sink.Id, out var last) && now - last < every))
                return;
            alive = alive.SetItem(sink.Id, now);
            var kind = AlertKind.AlertsAlive;
            Emit(sink with { Redaction = AlertRedaction.Public }, kind, now, 1, KeyFor(kind.Event, AlertSubject.None, setup.InstallKey), null, now);
        }

        public void Event(SinkDefinition sink, AlertEvent e, DateTimeOffset now)
        {
            var state = Load(now, sink.Id);
            var storm = Count(state.Storms.GetValueOrDefault(e.Kind.Event), now);
            state = state with { Storms = state.Storms.SetItem(e.Kind.Event, storm) };

            // In a storm every subject of the source shares one window, so the source is one alert per window.
            var subject = storm.Storming ? new AlertSubject(What: "storm") : e.Subject;
            var key = KeyFor(e.Kind.Event, subject, setup.InstallKey);
            var detail = sink.Redaction == AlertRedaction.Trusted && !storm.Storming ? DetailFor(e.Subject) : null;

            if (state.Windows.TryGetValue(key, out var open))
            {
                state = state with
                {
                    Windows = state.Windows.SetItem(key, open with { Repeats = open.Repeats + 1, FirstRepeatAt = open.FirstRepeatAt ?? e.At }),
                };
            }
            else
            {
                state = state with { Windows = state.Windows.SetItem(key, new(now, e.Kind, key, detail, 0, null)) };
                state = Send(sink, state, e.Kind, e.At, 1, key, detail, now);
            }
            sinks = sinks.SetItem(sink.Id, state);
        }

        public void Tick(SinkDefinition sink, DateTimeOffset now)
        {
            if (!sinks.TryGetValue(sink.Id, out var state))
                return;

            foreach (var window in state.Windows.Values.Where(w => now - w.Opened >= DedupeWindow).OrderBy(w => w.Opened).ToList())
            {
                state = state with { Windows = state.Windows.Remove(window.Key) };
                if (window.Repeats > 0 && (window.Kind.Severity >= sink.Threshold || window.Kind == AlertKind.AlertsFailing))
                    state = Send(sink, state, window.Kind, window.FirstRepeatAt!.Value, window.Repeats, window.Key, window.Detail, now);
            }

            state = state with
            {
                Normal = Release(sink, Refill(state.Normal, now, Cost, Burst), Cost, "normal"),
                Critical = Release(sink, Refill(state.Critical, now, CriticalCost, CriticalBurst), CriticalCost, "critical"),
                Storms = state.Storms.RemoveRange(state.Storms.Where(s => now - s.Value.MinuteStart >= 2 * StormMinute).Select(s => s.Key)),
            };
            sinks = sinks.SetItem(sink.Id, state);
        }

        SinkState Load(DateTimeOffset now, string sinkId) =>
            sinks.TryGetValue(sinkId, out var state)
                ? state with { Normal = Refill(state.Normal, now, Cost, Burst), Critical = Refill(state.Critical, now, CriticalCost, CriticalBurst) }
                : new(new(Burst * Cost, now, 0, null), new(CriticalBurst * CriticalCost, now, 0, null),
                    ImmutableDictionary<string, DedupeWindow>.Empty, ImmutableDictionary<string, StormCounter>.Empty);

        static StormCounter Count(StormCounter? counter, DateTimeOffset now)
        {
            if (counter is null)
                return new(now, 1, false);
            if (now - counter.MinuteStart < StormMinute)
                return counter with { Count = counter.Count + 1, Storming = counter.Storming || counter.Count + 1 > StormThreshold };
            // A new minute: the storm goes on only while the minute before it was one too.
            var stillStorming = now - counter.MinuteStart < 2 * StormMinute && counter.Count > StormThreshold;
            return new(now, 1, stillStorming);
        }

        /// <summary>Takes a token and sends, or counts the alert as held back.</summary>
        SinkState Send(SinkDefinition sink, SinkState state, AlertKind kind, DateTimeOffset at, int count, string key, TrustedDetail? detail, DateTimeOffset now)
        {
            var critical = kind.Severity == AlertSeverity.Critical;
            var bucket = critical ? state.Critical : state.Normal;
            var cost = critical ? CriticalCost : Cost;
            if (bucket.Credit >= cost)
            {
                bucket = bucket with { Credit = bucket.Credit - cost };
                Emit(sink, kind, at, count, key, detail, now);
            }
            else
            {
                bucket = bucket with { Suppressed = bucket.Suppressed + count, FirstSuppressedAt = bucket.FirstSuppressedAt ?? at };
            }
            return critical ? state with { Critical = bucket } : state with { Normal = bucket };
        }

        /// <summary>
        /// Once a bucket that held alerts back has a token again, one <c>alerts.suppressed</c> says how many
        /// occurrences it held (a held-back count summary adds its whole count).
        /// It ignores the sink's threshold: it is about that sink's own deliveries.
        /// </summary>
        Bucket Release(SinkDefinition sink, Bucket bucket, TimeSpan cost, string name)
        {
            if (bucket.Suppressed == 0 || bucket.Credit < cost)
                return bucket;
            var kind = AlertKind.AlertsSuppressed;
            Emit(sink, kind, bucket.FirstSuppressedAt!.Value, bucket.Suppressed, KeyFor(kind.Event, new(What: name), setup.InstallKey), null, bucket.RefilledAt);
            return bucket with { Credit = bucket.Credit - cost, Suppressed = 0, FirstSuppressedAt = null };
        }

        static Bucket Refill(Bucket bucket, DateTimeOffset now, TimeSpan cost, int burst)
        {
            if (now <= bucket.RefilledAt)
                return bucket;
            var credit = TimeSpan.FromTicks(Math.Min(burst * cost.Ticks, (bucket.Credit + (now - bucket.RefilledAt)).Ticks));
            return bucket with { Credit = credit, RefilledAt = now };
        }

        void Emit(SinkDefinition sink, AlertKind kind, DateTimeOffset at, int count, string key, TrustedDetail? detail, DateTimeOffset now)
        {
            var payload = new AlertPayload(NextId(now), kind.Event, kind.Severity, kind.Title, setup.Machine, at.ToUniversalTime(), count, key,
                sink.Redaction == AlertRedaction.Trusted ? detail : null);
            deliveries.Add(new(sink.Id, payload));
        }

        /// <summary>
        /// A ULID: 48 bits of milliseconds, then 80 bits of an HMAC over a sequence number, so ids are
        /// unique per install and unguessable without the planner reaching for a random source.
        /// </summary>
        string NextId(DateTimeOffset now)
        {
            Span<byte> bytes = stackalloc byte[16];
            var ms = (ulong)now.ToUnixTimeMilliseconds();
            for (var i = 0; i < 6; i++)
                bytes[i] = (byte)(ms >> (8 * (5 - i)));
            var mac = HMACSHA256.HashData(setup.InstallKey, Encoding.UTF8.GetBytes($"id:{sequence++}"));
            mac.AsSpan(0, 10).CopyTo(bytes[6..]);
            return Crockford(bytes);
        }

        static string Crockford(ReadOnlySpan<byte> bytes)
        {
            const string alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
            var value = new System.Numerics.BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            var chars = new char[26];
            for (var i = 25; i >= 0; i--)
            {
                chars[i] = alphabet[(int)(value & 31)];
                value >>= 5;
            }
            return new string(chars);
        }
    }
}
