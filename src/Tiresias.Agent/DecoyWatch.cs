using System.Net.Sockets;
using Tiresias.Audit;
using Tiresias.Decoys;
using Tiresias.Forwarder;

namespace Tiresias.Agent;

/// <summary>A decoy used, with the program that used it and the processes that started it (nearest first).</summary>
public sealed record DecoyTouch(DecoyHit Hit, IReadOnlyList<string> Parents)
{
    /// <summary>What was used, in the words of the activity log and the finding: a fact, nothing more.</summary>
    public string What => Hit.Use switch
    {
        DecoyUse.SqlPassword => "the decoy SQL password",
        DecoyUse.AdminToken => "the decoy admin token",
        DecoyUse.ApiKey => "the decoy API key",
        _ => "a decoy endpoint",
    };

    public string Process => Hit.ProcessId is { } pid ? $"{Hit.Program ?? "unknown program"} ({pid})" : "an unknown process";

    /// <summary>The activity record: what, where, who and who started it. Decoy values are never in it.</summary>
    public AuditRecord Record() => new(AuditKind.Deny, Consumer: "decoy", Service: What, Path: Hit.Endpoint, Process: Process,
        Reason: $"{Hit.Program ?? "An unknown program"} connected with {What}; started by {(Parents.Count > 0 ? string.Join(" < ", Parents) : "unknown")}");
}

/// <summary>
/// Hosts the decoys' loopback listeners while decoys are placed, following <c>decoys.json</c> as
/// <c>tir decoys</c> or the app change it, and reports each use with the process that made it.
/// </summary>
sealed class DecoyWatch : IDisposable
{
    readonly Lock gate = new();
    readonly FileSystemWatcher watcher;
    DecoyListener? listener;
    DecoySet? listening;

    public DecoyWatch()
    {
        Directory.CreateDirectory(KeyringStore.Directory);
        watcher = new(KeyringStore.Directory, DecoySet.FileName) { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size };
        watcher.Changed += (_, _) => Refresh();
        watcher.Created += (_, _) => Refresh();
        watcher.Deleted += (_, _) => Refresh();
        watcher.Renamed += (_, _) => Refresh();
    }

    public event Action<DecoyTouch>? Touched;

    public event Action<string>? Log;

    /// <summary>Whether the listeners are up: decoys are placed and their ports were free.</summary>
    public bool Listening
    {
        get
        {
            lock (gate)
                return listener is not null;
        }
    }

    public void Start()
    {
        watcher.EnableRaisingEvents = true;
        Refresh();
    }

    /// <summary>Starts, stops or moves the listeners to match <c>decoys.json</c>.</summary>
    void Refresh()
    {
        DecoySet? set;
        try
        {
            set = DecoyStore.Current is { Placed.Count: > 0 } placed ? placed : null;
        }
        catch (IOException)
        {
            // Mid-write: the watcher fires again when it is done.
            return;
        }
        lock (gate)
        {
            if (set?.HttpPort == listening?.HttpPort && set?.SqlPort == listening?.SqlPort && (set is null) == (listener is null))
            {
                listening = set;
                return;
            }
            Stop();
            if (set is null)
                return;
            var started = new DecoyListener(set, (client, port) => WindowsClientProcessLookup.Owner(client, port), TimeProvider.System);
            started.Hit += hit => Touched?.Invoke(new(hit, Parents(hit.ProcessId)));
            try
            {
                started.Start();
            }
            catch (SocketException e)
            {
                started.DisposeAsync().AsTask().GetAwaiter().GetResult();
                Log?.Invoke($"The decoys can't listen on ports {set.HttpPort} and {set.SqlPort} ({e.Message}); a use of one goes unseen.");
                return;
            }
            (listener, listening) = (started, set);
        }
    }

    static IReadOnlyList<string> Parents(int? pid) =>
        pid is { } id ? [.. ProcessTree.Ancestry(id).Skip(1).Select(p => $"{p.Program} ({p.ProcessId})")] : [];

    void Stop()
    {
        listener?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        (listener, listening) = (null, null);
    }

    public void Dispose()
    {
        watcher.Dispose();
        lock (gate)
            Stop();
    }
}
