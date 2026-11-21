namespace Tiresias.Decoys;

/// <summary>
/// One thread in a snapshot of every thread on the machine, as Windows reports it to any user
/// (<c>NtQuerySystemInformation</c>), even for processes the user can't open.
/// </summary>
/// <param name="State">The scheduler state; <see cref="OpenerNaming.Waiting"/> is the one that matters.</param>
/// <param name="WaitReason">Why it waits; a file open held by an oplock break waits as <see cref="OpenerNaming.Executive"/>.</param>
/// <param name="WaitStart">The interrupt tick (about 15.6 ms) its current wait began.</param>
public readonly record struct ThreadRow(int ProcessId, int ThreadId, int State, int WaitReason, uint WaitStart, uint ContextSwitches);

/// <summary>A process in the snapshot: its image file name as the snapshot gives it, and when it started (pids are reused).</summary>
public sealed record ProcessRow(int ProcessId, string Image, DateTimeOffset Started);

/// <summary>Every thread (or every one that may be an opener) and the processes they belong to, at one instant.</summary>
public sealed record ThreadSnapshot(IReadOnlyList<ThreadRow> Threads, IReadOnlyDictionary<int, ProcessRow> Processes);

/// <summary>Who opened a decoy file: one process, or "can't tell". Never a guess.</summary>
public abstract record DecoyOpener
{
    public sealed record Named(int ProcessId, string Image, DateTimeOffset Started) : DecoyOpener;

    public sealed record CantTell : DecoyOpener;

    public static readonly DecoyOpener Unknown = new CantTell();
}

/// <summary>
/// Names the process that opened an oplocked decoy file by the thread that wakes when the oplock
/// is released (docs/decoys.md, "The second spike"). The opener's thread waits (Executive) from the
/// tick the oplock broke until Tiresias releases it; threads that were waiting since that tick and
/// didn't move while Tiresias held the break are the candidates, and the ones whose wait ended
/// right after the release are the opener. Threads of exactly one process woke: that process. Of
/// none or of more than one: <see cref="DecoyOpener.Unknown"/>, since an innocent thread can wake
/// at the same instant, and an attacker can make one.
/// </summary>
public static class OpenerNaming
{
    /// <summary>KTHREAD_STATE Waiting.</summary>
    public const int Waiting = 5;

    /// <summary>KWAIT_REASON Executive.</summary>
    public const int Executive = 0;

    /// <summary>How many ticks before and after the break a candidate's wait may have begun: the break is read a little after the opener started waiting.</summary>
    public const int TicksBefore = 3, TicksAfter = 2;

    /// <summary>A thread that could be a paused opener: waiting as a held open does, outside the Idle and System processes.</summary>
    public static bool MayBeOpener(ThreadRow thread) =>
        thread.ProcessId > 4 && thread.State == Waiting && thread.WaitReason == Executive;

    /// <summary>
    /// The threads stuck since the break: waiting since a tick near <paramref name="breakTick"/> in
    /// the first snapshot, and still in that same wait, without a context switch, in every later one.
    /// </summary>
    /// <param name="settle">Snapshots taken while the break is held, oldest first.</param>
    public static IReadOnlyList<ThreadRow> Stuck(uint breakTick, IReadOnlyList<ThreadSnapshot> settle)
    {
        if (settle.Count == 0)
            return [];
        var later = settle.Skip(1).Select(Index).ToArray();
        return [.. settle[0].Threads.Where(t => MayBeOpener(t) && NearBreak(t.WaitStart, breakTick) && later.All(s => StillWaiting(t, s)))];
    }

    /// <summary>The opener among <paramref name="stuck"/>: the one process whose threads woke by <paramref name="released"/>.</summary>
    /// <param name="first">A snapshot the candidates were in, for the process's image and start time.</param>
    /// <param name="released">A snapshot taken just after the oplock was released.</param>
    public static DecoyOpener Name(IReadOnlyList<ThreadRow> stuck, ThreadSnapshot first, ThreadSnapshot released)
    {
        var after = Index(released);
        var woke = stuck.Where(t => !StillWaiting(t, after)).Select(t => t.ProcessId).Distinct().ToArray();
        return woke is [var pid] && first.Processes.TryGetValue(pid, out var process)
            ? new DecoyOpener.Named(pid, process.Image, process.Started)
            : DecoyOpener.Unknown;
    }

    /// <summary><see cref="Stuck"/> then <see cref="Name(IReadOnlyList{ThreadRow}, ThreadSnapshot, ThreadSnapshot)"/>.</summary>
    public static DecoyOpener Name(uint breakTick, IReadOnlyList<ThreadSnapshot> settle, ThreadSnapshot released) =>
        settle.Count == 0 ? DecoyOpener.Unknown : Name(Stuck(breakTick, settle), settle[0], released);

    /// <summary>The tick counter wraps (about every 776 days of uptime), so compare by difference.</summary>
    static bool NearBreak(uint waitStart, uint breakTick) =>
        unchecked((int)(waitStart - breakTick)) is >= -TicksBefore and <= TicksAfter;

    static bool StillWaiting(ThreadRow thread, IReadOnlyDictionary<(int, int), ThreadRow> snapshot) =>
        snapshot.TryGetValue((thread.ProcessId, thread.ThreadId), out var now) && MayBeOpener(now)
            && now.WaitStart == thread.WaitStart && now.ContextSwitches == thread.ContextSwitches;

    static Dictionary<(int, int), ThreadRow> Index(ThreadSnapshot snapshot)
    {
        var index = new Dictionary<(int, int), ThreadRow>(snapshot.Threads.Count);
        foreach (var thread in snapshot.Threads)
            index[(thread.ProcessId, thread.ThreadId)] = thread;
        return index;
    }
}
