using System.Net.Sockets;
using Tiresias.Audit;
using Tiresias.Client;
using Tiresias.Decoys;
using Tiresias.Forwarder;

namespace Tiresias.Agent;

/// <summary>
/// A decoy used, or a decoy file opened, with the program that did it and the processes that started
/// it (nearest first). <paramref name="Routine"/> names a routine opener (Windows Search, Defender…),
/// whose open is recorded and raises nothing. <paramref name="Frozen"/>: the admin tier froze the
/// program for this use and blocked its network.
/// </summary>
public sealed record DecoyTouch(DecoyHit Hit, IReadOnlyList<string> Parents, string? Routine = null, bool Frozen = false)
{
    /// <summary>What was used or done, in the words of the activity log and the finding: a fact, nothing more.</summary>
    public string What => Hit.Use switch
    {
        DecoyUse.SqlPassword => "the decoy SQL password",
        DecoyUse.AdminToken => "the decoy admin token",
        DecoyUse.ApiKey => "the decoy API key",
        DecoyUse.Read => DecoyReads.What(Hit.Endpoint),
        _ => "a decoy endpoint",
    };

    /// <summary>As every activity record names a process: <c>{image} (pid {pid})</c>.</summary>
    public string? Process => Hit.ProcessId is { } pid ? $"{Hit.Program ?? "unknown image"} (pid {pid})" : null;

    /// <summary>One line saying what happened, for the record and <c>tir agent</c>.</summary>
    public string Sentence => Hit.Use == DecoyUse.Read
        ? $"{Hit.Program ?? "A program Tiresias couldn't name"} {What}"
        : $"{Hit.Program ?? "An unknown program"} connected with {What}";

    /// <summary>The activity record: what, where, who and who started it. Decoy values are never in it.</summary>
    public AuditRecord Record() => new(AuditKind.Deny, Consumer: "decoy", Service: What, Path: Hit.Endpoint, Process: Process,
        Reason: Routine is { } routine
            ? $"{DecoyReads.RoutineReason} ({routine}): {Sentence}"
            : $"{Sentence}; started by {(Parents.Count > 0 ? string.Join(" < ", Parents) : "unknown")}{(Frozen ? "; " + Doctor.FrozenNote : "")}");
}

/// <summary>
/// Hosts the decoys' loopback listeners and the read tripwire on their files while decoys are
/// placed, following <c>decoys.json</c> as <c>tir decoys</c> or the app change it, and reports each
/// use or open with the process that made it.
/// </summary>
sealed class DecoyWatch : IDisposable
{
    readonly Lock gate = new();
    readonly FileSystemWatcher watcher;
    readonly DecoyHitFilter repeatedReads = new();
    readonly RoutineFolders routine = new(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        [Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)],
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        AppContext.BaseDirectory);
    DecoyListener? listener;
    DecoySet? listening;
    DecoyTripwire? tripwire;
    IReadOnlyList<string> watched = [];

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

    /// <summary>Starts, stops or moves the listeners, and the tripwire, to match <c>decoys.json</c>.</summary>
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
            Watch(set is null ? [] : DecoyPlan.Files(set));
            Listen(set);
        }
    }

    void Listen(DecoySet? set)
    {
        if (set?.HttpPort == listening?.HttpPort && set?.SqlPort == listening?.SqlPort && (set is null) == (listener is null))
        {
            listening = set;
            return;
        }
        StopListening();
        if (set is null)
            return;
        var started = new DecoyListener(set, (client, port) => WindowsClientProcessLookup.Owner(client, port), TimeProvider.System);
        started.Hit += hit => Touched?.Invoke(new(hit, Parents(hit.ProcessId, null)));
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

    void Watch(IReadOnlyList<string> files)
    {
        if (files.SequenceEqual(watched, StringComparer.OrdinalIgnoreCase))
            return;
        tripwire?.Dispose();
        (tripwire, watched) = (null, files);
        if (files.Count == 0)
            return;
        tripwire = new(files);
        tripwire.Log += message => Log?.Invoke(message);
        tripwire.Opened += Report;
        tripwire.Start();
    }

    void Report(DecoyFileOpened opened)
    {
        var named = opened.Opener as DecoyOpener.Named;
        var hit = new DecoyHit(DecoyUse.Read, opened.File, named?.ProcessId, opened.ImagePath ?? named?.Image, opened.At);
        if (!repeatedReads.ShouldReport(hit))
            return;
        var own = named?.ProcessId == Environment.ProcessId ? "Tiresias" : null;
        Touched?.Invoke(new(hit, Parents(named?.ProcessId, named?.Started), own ?? DecoyReads.RoutineOpener(opened.ImagePath, routine)));
    }

    /// <param name="started">When the process was known to start: a pid reused since gets no parents rather than someone else's.</param>
    static IReadOnlyList<string> Parents(int? pid, DateTimeOffset? started)
    {
        if (pid is not { } id)
            return [];
        var chain = ProcessTree.Ancestry(id);
        if (started is { } known && (chain.Count == 0 || Math.Abs((chain[0].Started - known.UtcDateTime).TotalSeconds) >= 1))
            return [];
        return [.. chain.Skip(1).Select(p => $"{p.Program} ({p.ProcessId})")];
    }

    void StopListening()
    {
        listener?.DisposeAsync().AsTask().GetAwaiter().GetResult();
        (listener, listening) = (null, null);
    }

    public void Dispose()
    {
        watcher.Dispose();
        lock (gate)
        {
            StopListening();
            tripwire?.Dispose();
            tripwire = null;
        }
    }
}
