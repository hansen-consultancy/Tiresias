using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>How a status item is marked in LcdHub's status strips; worse sorts first. LcdHub's own values.</summary>
public enum LcdHubLevel : byte
{
    Info,
    Warn,
    Bad,
}

/// <summary>One line in LcdHub's status strips, as Tiresias shows it.</summary>
/// <param name="Count">Occurrences since the item was last cleared.</param>
/// <param name="Until">When LcdHub drops it unless it is renewed.</param>
public sealed record LcdHubItem(string Key, string Title, LcdHubLevel Level, int Count, DateTimeOffset Until)
{
    public string Text => $"{Title} ×{Count}";
}

/// <summary>
/// What the alert frame for a <c>critical</c> alert shows (docs/alerts.md, <i>LcdHub alert frame</i>):
/// the severity, the event's title and its count, never more. The app draws it at each panel's size.
/// </summary>
/// <param name="Lines">Top to bottom; the first is the largest.</param>
public sealed record LcdHubCard(AlertSeverity Severity, IReadOnlyList<string> Lines);

/// <summary>Draws a card at a panel's size: <c>width × height</c> top-down BGRX pixels, as LcdHub takes them.</summary>
public delegate uint[] LcdHubRenderer(LcdHubCard card, int width, int height);

/// <summary>One of the hub's panels, as its Panels message announces it.</summary>
public sealed record LcdHubPanel(string Id, int Width, int Height);

/// <summary>
/// An alert as an LcdHub status item (docs/alerts.md, <i>Sinks</i>). Pure. Built from the event, the
/// title and the count alone, on a trusted sink too: the screen faces whoever stands at the desk, so
/// no <see cref="TrustedDetail"/> ever reaches it.
/// </summary>
public static class LcdHubFormat
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);

    /// <summary>A test alert only has to be seen once, not sit on the screen for a day.</summary>
    public static readonly TimeSpan TestLifetime = TimeSpan.FromMinutes(1);

    public static string Key(string alertEvent) => "tiresias:" + alertEvent;

    /// <summary>Whether a delivery also takes the panels over with an alert frame: <c>critical</c> only.</summary>
    public static bool TakesOver(AlertPayload payload) => payload.Severity == AlertSeverity.Critical;

    /// <summary>The frame for <paramref name="item"/>: its severity, title and count. Built from the item, so a trusted sink shows no more.</summary>
    public static LcdHubCard Card(LcdHubItem item, AlertSeverity severity) =>
        new(severity, [severity.ToString().ToUpperInvariant(), item.Title, $"×{item.Count} · Open Tiresias"]);

    public static LcdHubLevel Level(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical or AlertSeverity.High => LcdHubLevel.Bad,
        AlertSeverity.Warning => LcdHubLevel.Warn,
        _ => LcdHubLevel.Info,
    };

    /// <summary>
    /// The item after <paramref name="payload"/>: one per event, so its count adds up every delivery
    /// since the item was last cleared (a dedupe summary's <c>count</c> holds only the repeats), at the
    /// worst level seen, renewed for <paramref name="lifetime"/>.
    /// </summary>
    public static LcdHubItem Merge(LcdHubItem? shown, AlertPayload payload, DateTimeOffset now, TimeSpan lifetime)
    {
        var level = Level(payload.Severity);
        if (shown is null || shown.Until <= now)
            return new(Key(payload.Event), payload.Title, level, payload.Count, now + lifetime);
        var until = now + lifetime > shown.Until ? now + lifetime : shown.Until;
        return shown with { Level = level > shown.Level ? level : shown.Level, Count = shown.Count + payload.Count, Until = until };
    }
}

/// <summary>
/// LcdHub's producer wire, version 4 (github.com/stevehansen/LcdHub, <c>Client/LcdHubClient.cs</c>):
/// each message a little-endian u32 length of what follows, a u8 type, then its body; strings a u16
/// byte count and UTF-8. Tiresias sends Hello, Status and alert Frames, and reads only the hub's Panels.
/// </summary>
internal static class LcdHubWire
{
    public const string PipeName = "LcdHub";
    public const ushort Version = 4;
    const byte MsgHello = 1, MsgPanels = 2, MsgFrame = 3, MsgStatus = 6, StatusLifetime = 2;
    const byte FrameAlert = 1, FrameLifetime = 4;
    const int MaxMessageBytes = 16 << 20;
    const int MaxPanelPixels = (MaxMessageBytes - 1024) / 4;

    public static byte[] Hello(string name)
    {
        var w = new Writer(MsgHello);
        w.U16(Version);
        w.Str(name);
        return w.Done();
    }

    /// <summary>Key, text, u8 level, u8 flags, and with flag bit 1 a u32 lifetime in ms. Empty text withdraws the item.</summary>
    public static byte[] Status(string key, string text, LcdHubLevel level, uint lifetimeMs)
    {
        var w = new Writer(MsgStatus);
        w.Str(key);
        w.Str(text);
        w.U8((byte)level);
        w.U8(lifetimeMs > 0 ? StatusLifetime : (byte)0);
        if (lifetimeMs > 0)
            w.U32(lifetimeMs);
        return w.Done();
    }

    /// <summary>
    /// Panel id, u8 flags (1 alert, 4 lifetime), with flag 4 a u32 lifetime in ms, then <paramref name="pixels"/> as
    /// little-endian u32 BGRX. <paramref name="alert"/> takes the panel over; no pixels withdraws the frame.
    /// </summary>
    public static byte[] Frame(string panelId, bool alert, uint lifetimeMs, ReadOnlySpan<uint> pixels)
    {
        var w = new Writer(MsgFrame);
        w.Str(panelId);
        w.U8((byte)((alert ? FrameAlert : 0) | (lifetimeMs > 0 ? FrameLifetime : 0)));
        if (lifetimeMs > 0)
            w.U32(lifetimeMs);
        foreach (var pixel in pixels)
            w.U32(pixel);
        return w.Done();
    }

    /// <summary>A Panels body: u16 count, then per panel its id, u16 width and u16 height.</summary>
    /// <exception cref="IOException">Truncated, or a panel no frame could be sent to: empty, or more pixels than a message holds.</exception>
    public static IReadOnlyList<LcdHubPanel> Panels(ReadOnlySpan<byte> body)
    {
        try
        {
            var count = BinaryPrimitives.ReadUInt16LittleEndian(body);
            var at = 2;
            var panels = new List<LcdHubPanel>(count);
            for (var i = 0; i < count; i++)
            {
                var length = BinaryPrimitives.ReadUInt16LittleEndian(body[at..]);
                var id = Encoding.UTF8.GetString(body.Slice(at + 2, length));
                at += 2 + length;
                var width = BinaryPrimitives.ReadUInt16LittleEndian(body[at..]);
                var height = BinaryPrimitives.ReadUInt16LittleEndian(body[(at + 2)..]);
                // A lying hub is treated as gone, like a bad length: its sizes are untrusted input (I-101).
                if (width == 0 || height == 0 || (long)width * height > MaxPanelPixels)
                    throw new IOException("impossible panel size");
                panels.Add(new(id, width, height));
                at += 4;
            }
            return panels;
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new IOException("truncated panels message");
        }
    }

    /// <summary>Reads one message, keeping the body of a Panels message only.</summary>
    /// <returns><c>null</c> at a clean end of stream; else the panels it announced, or <c>null</c> panels for any other message.</returns>
    /// <exception cref="IOException">A bad length or a truncated message.</exception>
    public static async Task<(IReadOnlyList<LcdHubPanel>? Panels, bool More)> ReadAsync(Stream stream, CancellationToken ct)
    {
        var head = new byte[5];
        var read = await stream.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false, ct);
        if (read == 0)
            return (null, false);
        if (read < head.Length)
            throw new IOException("truncated message");
        var length = BinaryPrimitives.ReadInt32LittleEndian(head);
        if (length is < 1 or > MaxMessageBytes)
            throw new IOException("bad message length");
        var body = new byte[length - 1];
        if (await stream.ReadAtLeastAsync(body, body.Length, throwOnEndOfStream: false, ct) < body.Length)
            throw new IOException("truncated message");
        return (head[4] == MsgPanels ? Panels(body) : null, true);
    }

    /// <summary>Reads one message and drops it.</summary>
    /// <returns><c>false</c> at a clean end of stream.</returns>
    /// <exception cref="IOException">A bad length or a truncated message.</exception>
    public static async Task<bool> SkipAsync(Stream stream, CancellationToken ct)
    {
        var head = new byte[5];
        var read = await stream.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false, ct);
        if (read == 0)
            return false;
        if (read < head.Length)
            throw new IOException("truncated message");
        var length = BinaryPrimitives.ReadInt32LittleEndian(head);
        if (length is < 1 or > MaxMessageBytes)
            throw new IOException("bad message length");
        var body = new byte[length - 1];
        if (await stream.ReadAtLeastAsync(body, body.Length, throwOnEndOfStream: false, ct) < body.Length)
            throw new IOException("truncated message");
        return true;
    }

    sealed class Writer
    {
        readonly ArrayBufferWriter<byte> buffer = new();

        public Writer(byte type) => buffer.Write<byte>([0, 0, 0, 0, type]);

        public void U8(byte v) => buffer.Write<byte>([v]);

        public void U16(ushort v)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.GetSpan(2), v);
            buffer.Advance(2);
        }

        public void U32(uint v)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.GetSpan(4), v);
            buffer.Advance(4);
        }

        public void Str(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            if (bytes.Length > ushort.MaxValue)
                throw new ArgumentException("string too long", nameof(s));
            U16((ushort)bytes.Length);
            buffer.Write(bytes);
        }

        public byte[] Done()
        {
            var bytes = buffer.WrittenSpan.ToArray();
            BinaryPrimitives.WriteInt32LittleEndian(bytes, bytes.Length - 4);
            return bytes;
        }
    }
}

/// <summary>
/// Keeps Tiresias's status items on an LcdHub beside the machine, over the per-user pipe
/// <c>LcdHub</c> (docs/alerts.md, <i>Sinks</i>). LcdHub drops a producer's items when it disconnects,
/// so the link stays connected while it has an item to show, and only then: with nothing to show it
/// is not in the hub's producer list. It sends every item again, with what is left of its lifetime,
/// after the hub restarts or starts late. With no hub, items wait here until one appears or their
/// lifetime ends: delivering to a screen that isn't there is not a failure.
/// </summary>
public sealed class LcdHubLink : IAsyncDisposable
{
    /// <summary>The producer name the hub shows in its menu and remembers: keep it stable.</summary>
    public const string ProducerName = "Tiresias";

    public static readonly TimeSpan RetryEvery = TimeSpan.FromSeconds(5);
    static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(1);

    readonly string pipeName;
    readonly TimeProvider time;
    readonly Action<string> log;
    readonly Lock gate = new();
    readonly Dictionary<string, LcdHubItem> items = new(StringComparer.Ordinal);
    readonly HashSet<string> due = new(StringComparer.Ordinal);
    readonly HashSet<string> withdraw = new(StringComparer.Ordinal);
    readonly List<(string Key, TaskCompletionSource Done)> waiters = [];
    readonly LcdHubRenderer? render;
    IReadOnlyList<LcdHubPanel> panels = [];
    // The alert frame: which item it shows, at what severity, and whether the hub needs it (again) or must drop it.
    (string Key, AlertSeverity Severity)? frame;
    // The latest critical, which the frame goes back to when a test's frame ends.
    (string Key, AlertSeverity Severity)? critical;
    bool frameDue, frameWithdraw;
    readonly CancellationTokenSource stop = new();
    TaskCompletionSource signal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    Task? running;
    bool connected;

    /// <param name="pipeName">Tests pass their own; anything else uses LcdHub's.</param>
    /// <param name="render">Draws the alert frame for a <c>critical</c> alert; <c>null</c> shows status items only.</param>
    public LcdHubLink(TimeProvider time, Action<string> log, string pipeName = LcdHubWire.PipeName, LcdHubRenderer? render = null)
    {
        this.time = time;
        this.log = log;
        this.pipeName = pipeName;
        this.render = render;
    }

    /// <summary>The card the panels show now, if any.</summary>
    public LcdHubCard? Card
    {
        get
        {
            lock (gate)
                return CurrentCard(time.GetUtcNow());
        }
    }

    public bool Connected
    {
        get
        {
            lock (gate)
                return connected;
        }
    }

    /// <summary>What the strip should show now.</summary>
    public IReadOnlyList<LcdHubItem> Items
    {
        get
        {
            lock (gate)
                return [.. items.Values.Where(i => i.Until > time.GetUtcNow())];
        }
    }

    public void Show(AlertPayload payload) => Put(payload, LcdHubFormat.Lifetime);

    /// <summary>
    /// <b>Send a test alert</b>: shows <paramref name="payload"/> for <see cref="LcdHubFormat.TestLifetime"/>
    /// and waits up to <paramref name="wait"/> for it to reach a hub.
    /// </summary>
    /// <returns>Whether a hub got it; if not, it still shows when one starts within its lifetime.</returns>
    public async Task<bool> ShowAndWaitAsync(AlertPayload payload, TimeSpan wait, CancellationToken ct)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (gate)
            waiters.Add((Put(payload, LcdHubFormat.TestLifetime).Key, done));
        try
        {
            await done.Task.WaitAsync(wait, time, ct);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
        finally
        {
            lock (gate)
                waiters.RemoveAll(w => w.Done == done);
        }
    }

    /// <summary>Takes every Tiresias item off the hub: the user has seen the findings on Home.</summary>
    public void ClearAll()
    {
        lock (gate)
        {
            if (items.Count == 0)
                return;
            if (connected)
            {
                withdraw.UnionWith(items.Keys);
                frameWithdraw |= frame is not null;
            }
            items.Clear();
            due.Clear();
            frame = critical = null;
            frameDue = false;
            Wake();
        }
    }

    LcdHubItem Put(AlertPayload payload, TimeSpan lifetime)
    {
        LcdHubItem item;
        lock (gate)
        {
            var key = LcdHubFormat.Key(payload.Event);
            items[key] = item = LcdHubFormat.Merge(items.GetValueOrDefault(key), payload, time.GetUtcNow(), lifetime);
            withdraw.Remove(key);
            due.Add(key);
            if (render is not null && (LcdHubFormat.TakesOver(payload) || lifetime == LcdHubFormat.TestLifetime))
            {
                // The latest critical takes the panels, or a test shows what one looks like; a later non-critical leaves it.
                frame = (key, payload.Severity);
                if (LcdHubFormat.TakesOver(payload))
                    critical = frame;
                frameDue = true;
                frameWithdraw = false;
            }
            else if (frame?.Key == key)
                frameDue = true;
            running ??= Task.Run(() => RunAsync(stop.Token));
            Wake();
        }
        return item;
    }

    void Wake() => signal.TrySetResult();

    Task NextWake()
    {
        lock (gate)
        {
            if (signal.Task.IsCompleted)
                signal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            return signal.Task;
        }
    }

    bool HasItems()
    {
        lock (gate)
        {
            Prune(time.GetUtcNow());
            return items.Count > 0;
        }
    }

    async Task RunAsync(CancellationToken ct)
    {
        var missing = false;
        while (!ct.IsCancellationRequested)
        {
            var wake = NextWake();
            if (!HasItems())
            {
                await wake.WaitAsync(ct);
                continue;
            }
            var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.CurrentUserOnly | PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync(ConnectTimeout, ct);
            }
            catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException)
            {
                // No hub, or one run by another user (CurrentUserOnly refuses it): wait and try again.
                await pipe.DisposeAsync();
                if (!missing)
                    log($"alerts: no LcdHub to show items on ({e.GetType().Name}); trying every {RetryEvery.TotalSeconds:0} s");
                missing = true;
                await Task.Delay(RetryEvery, time, ct);
                continue;
            }
            missing = false;
            await using (pipe)
                await ServeAsync(pipe, ct);
        }
    }

    /// <summary>One connection: hello, every item, then changes as they come, until nothing is left to show or the hub goes.</summary>
    async Task ServeAsync(Stream pipe, CancellationToken ct)
    {
        using var reading = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task<bool>? reader = null;
        try
        {
            lock (gate)
            {
                connected = true;
                withdraw.Clear();
                due.UnionWith(items.Keys);
                panels = [];
                frameWithdraw = false;
            }
            log("alerts: LcdHub connected");
            await pipe.WriteAsync(LcdHubWire.Hello(ProducerName), ct);
            reader = ReadAsync(pipe, reading.Token);
            while (!ct.IsCancellationRequested)
            {
                var wake = NextWake();
                var (messages, delivered, next, draw) = Collect();
                foreach (var message in messages)
                    await pipe.WriteAsync(message, ct);
                // Drawn outside the lock: the renderer may wait for the app's UI thread, which may be in Show.
                if (draw is var (card, lifetimeMs, onto))
                    foreach (var panel in onto)
                        await pipe.WriteAsync(LcdHubWire.Frame(panel.Id, alert: true, lifetimeMs, Draw(card, panel)), ct);
                await pipe.FlushAsync(ct);
                foreach (var done in delivered)
                    done.TrySetResult();
                // Nothing left: disconnecting drops whatever is left on the hub, and takes Tiresias out of its list.
                if (next is null)
                    return;
                using var sleeping = CancellationTokenSource.CreateLinkedTokenSource(ct);
                await Task.WhenAny(wake, reader, Task.Delay(next.Value, time, sleeping.Token));
                await sleeping.CancelAsync();
                if (reader.IsCompleted)
                {
                    log("alerts: LcdHub went away");
                    await Task.Delay(RetryEvery, time, ct);
                    return;
                }
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            log($"alerts: LcdHub went away ({e.GetType().Name})");
            await Task.Delay(RetryEvery, time, ct);
        }
        finally
        {
            lock (gate)
                connected = false;
            await reading.CancelAsync();
            if (reader is not null)
                await reader.ContinueWith(_ => { }, TaskScheduler.Default);
        }
    }

    /// <summary>The card in pixels at <paramref name="panel"/>'s size, or black if the renderer fails or gets the size wrong (the hub would drop that).</summary>
    uint[] Draw(LcdHubCard card, LcdHubPanel panel)
    {
        try
        {
            var pixels = render!(card, panel.Width, panel.Height);
            if (pixels.Length == panel.Width * panel.Height)
                return pixels;
            log($"alerts: LcdHub frame drawn at the wrong size for a {panel.Width}x{panel.Height} panel");
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // A frame that won't draw mustn't take the status items down with it.
            log($"alerts: LcdHub frame not drawn ({e.GetType().Name})");
        }
        return new uint[panel.Width * panel.Height];
    }

    /// <summary>The frame's card while its item is shown.</summary>
    LcdHubCard? CurrentCard(DateTimeOffset now) =>
        frame is var (key, severity) && items.TryGetValue(key, out var item) && item.Until > now ? LcdHubFormat.Card(item, severity) : null;

    /// <summary>
    /// What to write now, the waiters it satisfies, how long until the next item expires (<c>null</c>:
    /// nothing left), and the frame to draw on each panel, if it is due.
    /// </summary>
    (List<byte[]> Messages, List<TaskCompletionSource> Delivered, TimeSpan? Next, (LcdHubCard Card, uint LifetimeMs, IReadOnlyList<LcdHubPanel> Panels)? Draw) Collect()
    {
        lock (gate)
        {
            var now = time.GetUtcNow();
            Prune(now);
            var messages = new List<byte[]>();
            if (frameWithdraw)
                foreach (var panel in panels)
                    messages.Add(LcdHubWire.Frame(panel.Id, alert: false, 0, []));
            frameWithdraw = false;
            (LcdHubCard, uint, IReadOnlyList<LcdHubPanel>)? draw = null;
            if (frameDue && panels.Count > 0 && CurrentCard(now) is { } card)
            {
                var left = Math.Clamp((items[frame!.Value.Key].Until - now).TotalMilliseconds, 1, uint.MaxValue);
                draw = (card, (uint)left, panels);
                frameDue = false;
            }
            foreach (var key in withdraw)
                messages.Add(LcdHubWire.Status(key, "", LcdHubLevel.Info, 0));
            withdraw.Clear();
            foreach (var key in due)
            {
                var item = items[key];
                var left = Math.Clamp((item.Until - now).TotalMilliseconds, 1, uint.MaxValue);
                messages.Add(LcdHubWire.Status(item.Key, item.Text, item.Level, (uint)left));
            }
            due.Clear();
            // Put marks an item due, so the first write after it carries it: a waiter whose item is still here got it.
            var delivered = waiters.Where(w => items.ContainsKey(w.Key)).Select(w => w.Done).ToList();
            TimeSpan? next = items.Count == 0 ? null : items.Values.Min(i => i.Until) - now;
            return (messages, delivered, next, draw);
        }
    }

    /// <summary>Drops expired items; the hub drops them by itself, from the lifetime it was sent.</summary>
    void Prune(DateTimeOffset now)
    {
        foreach (var key in items.Where(i => i.Value.Until <= now).Select(i => i.Key).ToList())
        {
            items.Remove(key);
            due.Remove(key);
        }
        // The hub drops the frame by itself too: it was sent with its item's lifetime.
        if (critical is var (live, _) && !items.ContainsKey(live))
            critical = null;
        if (frame is var (shown, _) && !items.ContainsKey(shown))
            (frame, frameDue) = (critical, critical is not null);
    }

    /// <summary>
    /// Reads what the hub sends until it goes. Keeps its panels: a new list means it forgot every frame,
    /// so the alert frame is due again at the new sizes. Style and visibility are dropped: an alert
    /// frame is drawn in its own colours and sent even to a hidden panel, as LcdHub asks of alerts.
    /// </summary>
    async Task<bool> ReadAsync(Stream pipe, CancellationToken ct)
    {
        try
        {
            while (await LcdHubWire.ReadAsync(pipe, ct) is { More: true } message)
            {
                if (message.Panels is not { } announced)
                    continue;
                lock (gate)
                {
                    panels = announced;
                    frameDue |= frame is not null;
                    Wake();
                }
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException)
        {
        }
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        Task? run;
        lock (gate)
            run = running;
        if (run is not null)
        {
            try
            {
                await run;
            }
            catch (OperationCanceledException)
            {
            }
        }
        stop.Dispose();
    }
}
