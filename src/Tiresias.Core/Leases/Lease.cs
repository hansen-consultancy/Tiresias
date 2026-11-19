namespace Tiresias.Leases;

/// <param name="MaxDuration">Longest a lease may run, whatever time it starts.</param>
/// <param name="DailyCutoff">Local time a lease ends at regardless, e.g. 20:00, so a lease opened in the morning can't run into the night.</param>
/// <param name="HeartbeatTimeout">The Keyring must check in at least this often, or the lease ends (laptop gone, asleep, unplugged from NetBird).</param>
public sealed record LeaseTerms(TimeSpan MaxDuration, TimeOnly DailyCutoff, TimeSpan HeartbeatTimeout, TimeZoneInfo Zone)
{
    public static LeaseTerms Workday(TimeZoneInfo zone) =>
        new(TimeSpan.FromHours(10), new TimeOnly(20, 0), TimeSpan.FromMinutes(15), zone);
}

public enum LeaseEnd
{
    None,
    /// <summary><c>tir lock</c>, workstation lock, sleep or logoff.</summary>
    Revoked,
    HardCap,
    HeartbeatLost,
}

/// <summary>
/// The broker's view of one lease: when it ends, and which grants are elevated right now. Holds no
/// key material itself; the broker drops the leased DEKs the moment <see cref="Evaluate"/> stops
/// returning <see cref="LeaseEnd.None"/>. Once ended, a lease never comes back: a new Hello prompt
/// opens a new lease.
/// </summary>
public sealed class Lease
{
    readonly Dictionary<(string Service, string Grant), DateTimeOffset> elevations = [];
    LeaseEnd ended;

    Lease(string id, DateTimeOffset startedAt, DateTimeOffset hardCapAt, TimeSpan heartbeatTimeout)
    {
        Id = id;
        StartedAt = startedAt;
        HardCapAt = hardCapAt;
        HeartbeatTimeout = heartbeatTimeout;
        LastHeartbeat = startedAt;
    }

    public string Id { get; }
    public DateTimeOffset StartedAt { get; }
    public DateTimeOffset HardCapAt { get; }
    public TimeSpan HeartbeatTimeout { get; }
    public DateTimeOffset LastHeartbeat { get; private set; }

    public static Lease Begin(string id, DateTimeOffset now, LeaseTerms terms) =>
        new(id, now, HardCap(now, terms), terms.HeartbeatTimeout);

    /// <summary>
    /// The earlier of <c>start + MaxDuration</c> and the first daily cutoff strictly after start, in
    /// the configured zone (so DST shifts move the cutoff with the wall clock, as a person expects).
    /// </summary>
    public static DateTimeOffset HardCap(DateTimeOffset start, LeaseTerms terms)
    {
        var local = TimeZoneInfo.ConvertTime(start, terms.Zone);
        var cutoffDate = DateOnly.FromDateTime(local.DateTime);
        if (TimeOnly.FromDateTime(local.DateTime) >= terms.DailyCutoff)
            cutoffDate = cutoffDate.AddDays(1);

        var cutoffLocal = cutoffDate.ToDateTime(terms.DailyCutoff, DateTimeKind.Unspecified);
        var cutoff = new DateTimeOffset(cutoffLocal, terms.Zone.GetUtcOffset(cutoffLocal));

        var byDuration = start + terms.MaxDuration;
        return cutoff < byDuration ? cutoff : byDuration;
    }

    public LeaseEnd Evaluate(DateTimeOffset now)
    {
        if (ended != LeaseEnd.None)
            return ended;
        if (now >= HardCapAt)
            return ended = LeaseEnd.HardCap;
        if (now - LastHeartbeat > HeartbeatTimeout)
            return ended = LeaseEnd.HeartbeatLost;
        return LeaseEnd.None;
    }

    /// <returns><c>false</c> when the lease had already ended; a heartbeat never revives one.</returns>
    public bool Heartbeat(DateTimeOffset now)
    {
        if (Evaluate(now) != LeaseEnd.None)
            return false;
        LastHeartbeat = now;
        return true;
    }

    public void Revoke()
    {
        if (ended == LeaseEnd.None)
            ended = LeaseEnd.Revoked;
        elevations.Clear();
    }

    /// <summary>Records an approved elevation (after its own Hello prompt). It never outlives the lease.</summary>
    /// <returns>When it expires, or <c>null</c> when the lease has ended.</returns>
    public DateTimeOffset? Elevate(string service, string grant, TimeSpan duration, DateTimeOffset now)
    {
        if (Evaluate(now) != LeaseEnd.None)
            return null;
        var requested = now + duration;
        var expires = requested < HardCapAt ? requested : HardCapAt;
        elevations[(service, grant)] = expires;
        return expires;
    }

    /// <summary>Ends every elevation of a service, e.g. when its policy changed after it was approved.</summary>
    public void DropElevations(string service)
    {
        foreach (var key in elevations.Keys.Where(k => k.Service == service).ToArray())
            elevations.Remove(key);
    }

    public IReadOnlySet<string> ActiveElevations(string service, DateTimeOffset now) =>
        Evaluate(now) != LeaseEnd.None
            ? new HashSet<string>()
            : elevations.Where(e => e.Key.Service == service && now < e.Value).Select(e => e.Key.Grant).ToHashSet();
}
