using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Tiresias.Agent;
using Tiresias.AdminTier;
using Tiresias.Decoys;
using Tiresias.Forwarder;

namespace Tiresias.Admin;

/// <summary>
/// The decoy sets the service holds, one per user (<c>decoys\&lt;sid&gt;.json</c> in its state
/// folder), each listened for on loopback from start (<see cref="DecoyListener"/>), and each use
/// queued for its user (<c>events\&lt;sid&gt;.json</c>) until that user's app acknowledges it. A
/// set whose ports are taken is tried again every few seconds: the user's agent may still hold them
/// for a moment after adopting. Reads of each set's files are audited (<see cref="ReadAudit"/>)
/// and queued the same way. A use (never a read) by a process that can be named freezes it and
/// blocks its network (<see cref="Freezer"/>), before it is queued.
/// </summary>
sealed class DecoyHold : IAsyncDisposable
{
    static readonly TimeSpan Retry = TimeSpan.FromSeconds(5);

    readonly string decoysFolder;
    readonly string eventsFolder;
    readonly ILogger logger;
    readonly Lock gate = new();
    readonly Dictionary<string, Held> held = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, AdminEventQueue> queues = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, TaskCompletionSource> arrived = new(StringComparer.OrdinalIgnoreCase);
    readonly Timer retry;
    readonly ReadAudit audit;
    readonly Freezer freezer;
    bool tornDown;

    sealed class Held(AdminHeldDecoys decoys)
    {
        public AdminHeldDecoys Decoys { get; } = decoys;
        public DecoyListener? Listener { get; set; }
    }

    public DecoyHold(string stateFolder, Freezer freezer, ILogger logger)
    {
        this.freezer = freezer;
        decoysFolder = Path.Combine(stateFolder, "decoys");
        eventsFolder = Path.Combine(stateFolder, "events");
        this.logger = logger;
        Directory.CreateDirectory(decoysFolder);
        Directory.CreateDirectory(eventsFolder);
        foreach (var file in Directory.EnumerateFiles(decoysFolder, "*.json"))
        {
            var sid = Path.GetFileNameWithoutExtension(file);
            if (AdminArgs.UserSid(sid) && AdminHeldDecoys.Parse(File.ReadAllText(file)) is { } decoys)
                held[sid] = new(decoys);
        }
        audit = new(stateFolder, logger, Queue);
        foreach (var (sid, h) in held)
            audit.Hold(sid, h.Decoys.Files);
        audit.Settle(held.Count);
        retry = new(_ => ListenAll(), null, TimeSpan.Zero, Retry);
    }

    /// <returns><c>null</c> once held, or why not.</returns>
    public string? Adopt(string sid, AdminHeldDecoys decoys)
    {
        lock (gate)
        {
            if (held.ContainsKey(sid))
                return "the admin tier already holds decoys for this user; release them first";
            Write(SetPath(sid), decoys.ToJson());
            held[sid] = new(decoys);
        }
        audit.Hold(sid, decoys.Files);
        ListenAll();
        return null;
    }

    public AdminDecoysStatus Status(string sid)
    {
        lock (gate)
            return held.TryGetValue(sid, out var h) ? h.Decoys.Status(h.Listener is not null, audit.Auditing(sid)) : new(false, false, [], 0);
    }

    /// <summary>Stops listening for the user's set and forgets it; <c>null</c> when none is held.</summary>
    public async Task<DecoySet?> ReleaseAsync(string sid)
    {
        Held? released;
        int left;
        lock (gate)
        {
            if (!held.Remove(sid, out released))
                return null;
            File.Delete(SetPath(sid));
            left = held.Count;
        }
        audit.Release(sid, released.Decoys.Files, left);
        if (released.Listener is { } listener)
            await listener.DisposeAsync();
        return released.Decoys.Set;
    }

    /// <summary>
    /// Drops the acknowledged events, then answers what is queued for the user, waiting up to
    /// <paramref name="wait"/> for one when nothing is.
    /// </summary>
    public async Task<IReadOnlyList<AdminEvent>> WaitAsync(string sid, IReadOnlyList<long> ack, TimeSpan wait, CancellationToken ct)
    {
        Task signal;
        lock (gate)
        {
            var queue = Queue(sid);
            if (ack.Count > 0)
            {
                queue = queue.Ack(ack);
                Save(sid, queue);
            }
            if (queue.Pending.Count > 0 || wait <= TimeSpan.Zero)
                return queue.Pending;
            if (!arrived.TryGetValue(sid, out var waiting))
                arrived[sid] = waiting = new(TaskCreationOptions.RunContinuationsAsynchronously);
            signal = waiting.Task;
        }
        try
        {
            await signal.WaitAsync(wait, ct);
        }
        catch (TimeoutException)
        {
        }
        lock (gate)
            return Queue(sid).Pending;
    }

    void ListenAll()
    {
        List<(string Sid, Held Held)> idle;
        lock (gate)
            idle = tornDown ? [] : [.. held.Where(h => h.Value.Listener is null).Select(h => (h.Key, h.Value))];
        foreach (var (sid, h) in idle)
        {
            var set = h.Decoys.Set;
            var listener = new DecoyListener(set, (client, port) => TcpConnectionOwner.Owner(client, port), TimeProvider.System);
            listener.Hit += hit => Queue(sid, hit);
            try
            {
                listener.Start();
            }
            catch (SocketException)
            {
                listener.DisposeAsync().AsTask().GetAwaiter().GetResult();
                continue;
            }
            lock (gate)
            {
                // Released meanwhile: nothing is to listen for it now.
                if (held.TryGetValue(sid, out var still) && ReferenceEquals(still, h) && h.Listener is null)
                {
                    h.Listener = listener;
                    continue;
                }
            }
            listener.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    /// <summary>A use: frozen first, while the parents are still there to be named.</summary>
    void Queue(string sid, DecoyHit hit)
    {
        IReadOnlyList<string> parents = hit.ProcessId is { } pid ? [.. ProcessTree.Ancestry(pid).Skip(1).Select(p => $"{p.Program} ({p.ProcessId})")] : [];
        var frozen = false;
        if (hit.ProcessId is { } id)
        {
            var (done, refusal) = freezer.Freeze(sid, id);
            frozen = done is not null;
            if (refusal is not null)
                logger.LogWarning("A program that used a decoy wasn't frozen: {Reason}", refusal);
        }
        Queue(sid, hit, parents, null, frozen);
    }

    void Queue(string sid, DecoyHit hit, IReadOnlyList<string> parents, string? routine) => Queue(sid, hit, parents, routine, false);

    void Queue(string sid, DecoyHit hit, IReadOnlyList<string> parents, string? routine, bool frozen)
    {
        lock (gate)
        {
            var (queue, _) = Queue(sid).Add(hit, parents, routine, frozen);
            Save(sid, queue);
            if (arrived.Remove(sid, out var waiting))
                waiting.TrySetResult();
        }
    }

    AdminEventQueue Queue(string sid)
    {
        if (!queues.TryGetValue(sid, out var queue))
        {
            var path = EventsPath(sid);
            queues[sid] = queue = AdminEventQueue.Parse(File.Exists(path) ? File.ReadAllText(path) : null);
        }
        return queue;
    }

    void Save(string sid, AdminEventQueue queue)
    {
        queues[sid] = queue;
        try
        {
            Write(EventsPath(sid), queue.ToJson());
        }
        catch (IOException e)
        {
            // Still queued in memory: only a restart before the app reads it loses it.
            logger.LogError("An event queue can't be written: {Kind}", e.GetType().Name);
        }
    }

    string SetPath(string sid) => Path.Combine(decoysFolder, sid + ".json");

    string EventsPath(string sid) => Path.Combine(eventsFolder, sid + ".json");

    static void Write(string path, string text)
    {
        var temp = path + ".tmp";
        File.WriteAllText(temp, text);
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>
    /// For the tier's removal: stops listening and takes the audit rules off (and the policy back),
    /// for good until the service starts again. The sets stay in the state folder, for the removal
    /// to hand back once the service has stopped.
    /// </summary>
    public async Task TearDownAsync()
    {
        List<(string Sid, Held Held)> all;
        lock (gate)
        {
            tornDown = true;
            all = [.. held.Select(h => (h.Key, h.Value))];
        }
        var left = all.Count;
        foreach (var (sid, h) in all)
        {
            audit.Release(sid, h.Decoys.Files, --left);
            DecoyListener? listener;
            lock (gate)
                (listener, h.Listener) = (h.Listener, null);
            if (listener is not null)
                await listener.DisposeAsync();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await retry.DisposeAsync();
        audit.Dispose();
        List<DecoyListener> listeners;
        lock (gate)
        {
            listeners = [.. held.Values.Select(h => h.Listener).OfType<DecoyListener>()];
            foreach (var h in held.Values)
                h.Listener = null;
        }
        foreach (var listener in listeners)
            await listener.DisposeAsync();
    }
}
