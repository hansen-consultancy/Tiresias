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
/// recorded for its user in the protected incident journal. A
/// set whose ports are taken is tried again every few seconds: the user's agent may still hold them
/// for a moment after adopting. Reads of each set's files are audited (<see cref="ReadAudit"/>)
/// and recorded the same way. A use (never a read) by a process that can be named freezes it and
/// blocks its network (<see cref="Freezer"/>), before it is recorded.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
sealed class DecoyHold : IAsyncDisposable
{
    static readonly TimeSpan Retry = TimeSpan.FromSeconds(5);

    readonly string decoysFolder;
    readonly string eventsFolder;
    readonly ILogger logger;
    readonly Lock gate = new();
    readonly Dictionary<string, Held> held = new(StringComparer.OrdinalIgnoreCase);
    readonly System.Collections.Concurrent.ConcurrentDictionary<string, Incidents> incidents = new(StringComparer.OrdinalIgnoreCase);
    readonly Timer retry;
    readonly ReadAudit audit;
    readonly Freezer freezer;
    bool tornDown;

    sealed class Incidents(string folder, string sid)
    {
        public readonly Lazy<AdminIncidentJournal> Journal = new(() => new(folder, sid));
        public TaskCompletionSource? Arrived;
    }

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
        audit = new(stateFolder, logger, Record);
        foreach (var (sid, h) in held.Where(h => h.Value.Decoys.Verified))
            audit.Hold(sid, h.Decoys.Files);
        audit.Settle(held.Count(h => h.Value.Decoys.Verified));
        retry = new(_ => ListenAll(), null, TimeSpan.Zero, Retry);
    }

    /// <returns><c>null</c> once held, or why not.</returns>
    public string? Adopt(string sid, AdminHeldDecoys decoys)
    {
        lock (gate)
        {
            if (!decoys.MatchesManifest())
                return "the files do not match the placed decoys";
            if (held.TryGetValue(sid, out var existing) && existing.Decoys.Verified)
                return existing.Decoys.Set.ToJson() == decoys.Set.ToJson() ? null : "the admin tier already holds decoys for this user; release them first";
            Write(SetPath(sid), decoys.ToJson());
            held[sid] = new(decoys);
        }
        if (decoys.Verified)
            audit.Hold(sid, decoys.Files);
        ListenAll();
        return null;
    }

    public AdminDecoysStatus Status(string sid)
    {
        lock (gate)
            return held.TryGetValue(sid, out var h) ? h.Decoys.Status(h.Listener is not null, audit.Auditing(sid)) : new(false, false, [], 0);
    }

    public AdminDecoysRelease PrepareRelease(string sid)
    {
        lock (gate)
            return held.TryGetValue(sid, out var h) ? new(sid, h.Decoys.Set, h.Decoys.ReleaseReceipt()) : new(sid, null);
    }

    /// <summary>Forgets only the exact protected snapshot the elevated helper handed back.</summary>
    public async Task<bool> CommitReleaseAsync(string sid, string receipt)
    {
        Held? released;
        int left;
        lock (gate)
        {
            if (!held.TryGetValue(sid, out released))
                return true;
            if (released.Decoys.ReleaseReceipt() != receipt)
                return false;
            File.Delete(SetPath(sid));
            held.Remove(sid);
            left = held.Count(h => h.Value.Decoys.Verified);
        }
        if (released.Decoys.Verified)
            audit.Release(sid, released.Decoys.Files, left);
        if (released.Listener is { } listener)
            await listener.DisposeAsync();
        return true;
    }

    Incidents For(string sid) => incidents.GetOrAdd(sid, id => new(eventsFolder, id));

    public async Task<AdminEvents> WaitAsync(string sid, long after, TimeSpan wait, CancellationToken ct)
    {
        var account = For(sid);
        Task signal;
        lock (account)
        {
            var page = account.Journal.Value.Read(after, pendingOnly: true);
            if (page.Events.Count != 0 || wait <= TimeSpan.Zero)
                return page;
            account.Arrived ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            signal = account.Arrived.Task;
        }
        try
        {
            await signal.WaitAsync(wait, ct);
        }
        catch (TimeoutException) { }
        lock (account)
            return account.Journal.Value.Read(after, pendingOnly: true);
    }

    public AdminEvents History(string sid, long after) => WithJournal(sid, j => j.Read(after, pendingOnly: false));

    public AdminEvents Review(string sid, long through) => WithJournal(sid, j => j.Review(through));

    public AdminBlockStatus Check(string sid, string? program, string? sha256) => WithJournal(sid, j => j.Check(program, sha256));

    public AdminBlocks Blocks(string sid, string? after) => WithJournal(sid, j => j.List(after));

    public AdminBlockStatus Unblock(string sid, string program) => WithJournal(sid, j => j.Unblock(program));

    T WithJournal<T>(string sid, Func<AdminIncidentJournal, T> action)
    {
        var account = For(sid);
        lock (account)
            return action(account.Journal.Value);
    }

    void ListenAll()
    {
        List<(string Sid, Held Held)> idle;
        lock (gate)
            idle = tornDown ? [] : [.. held.Where(h => h.Value.Decoys.Verified && h.Value.Listener is null).Select(h => (h.Key, h.Value))];
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
        IReadOnlyList<string> parents = hit.ProcessId is { } pid
            ? [.. ProcessTree.Ancestry(pid).Skip(1).Select(p => $"{p.Program} ({p.ProcessId})")]
            : [];
        var frozen = false;
        if (hit.ProcessId is { } id)
        {
            var (done, refusal) = freezer.Freeze(sid, id);
            frozen = done is not null;
            if (refusal is not null)
                logger.LogWarning("A program that used a decoy wasn't frozen: {Reason}", refusal);
        }
        Record(sid, hit, parents, null, frozen);
    }

    /// <summary>A read of a held file, from <see cref="ReadAudit"/>.</summary>
    void Record(string sid, DecoyHit hit, IReadOnlyList<string> parents, string? routine) => Record(sid, hit, parents, routine, false);

    void Record(string sid, DecoyHit hit, IReadOnlyList<string> parents, string? routine, bool frozen)
    {
        // Once a hit is received, this user's decisions wait for its measurement and durable commit.
        var account = For(sid);
        lock (account)
        {
            try
            {
                account.Journal.Value.Record(hit, parents, PipeCallerIdentity.ImageDigest(hit), routine, frozen);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
            {
                logger.LogError("An incident could not be recorded: {Kind}", e.GetType().Name);
            }
            account.Arrived?.TrySetResult();
            account.Arrived = null;
        }
    }

    string SetPath(string sid) => Path.Combine(decoysFolder, sid + ".json");

    static void Write(string path, string text)
    {
        var temp = path + ".tmp";
        using (var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            file.Write(System.Text.Encoding.UTF8.GetBytes(text));
            file.Flush(flushToDisk: true);
        }
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
            all = [.. held.Where(h => h.Value.Decoys.Verified).Select(h => (h.Key, h.Value))];
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
