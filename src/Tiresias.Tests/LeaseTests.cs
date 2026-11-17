using Tiresias.Leases;

namespace Tiresias.Tests;

public class LeaseTests
{
    static readonly TimeZoneInfo Brussels = TimeZoneInfo.FindSystemTimeZoneById("Europe/Brussels");
    static readonly LeaseTerms Workday = LeaseTerms.Workday(Brussels);

    static DateTimeOffset Local(int year, int month, int day, int hour, int minute = 0)
    {
        var dt = new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Unspecified);
        return new DateTimeOffset(dt, Brussels.GetUtcOffset(dt));
    }

    [Test]
    public void Morning_lease_is_capped_by_duration() =>
        Assert.That(Lease.HardCap(Local(2026, 11, 17, 8), Workday), Is.EqualTo(Local(2026, 11, 17, 18)));

    [Test]
    public void Afternoon_lease_is_capped_by_the_daily_cutoff() =>
        Assert.That(Lease.HardCap(Local(2026, 11, 17, 14), Workday), Is.EqualTo(Local(2026, 11, 17, 20)));

    [Test]
    public void Lease_opened_after_the_cutoff_runs_its_duration_not_until_tomorrows_cutoff() =>
        Assert.That(Lease.HardCap(Local(2026, 11, 17, 21), Workday), Is.EqualTo(Local(2026, 11, 18, 7)));

    [Test]
    public void Lease_opened_exactly_at_the_cutoff_is_not_capped_to_zero() =>
        Assert.That(Lease.HardCap(Local(2026, 11, 17, 20), Workday), Is.EqualTo(Local(2026, 11, 18, 6)));

    [Test]
    public void Cutoff_follows_the_wall_clock_across_dst()
    {
        // 2026-03-29: Brussels jumps from 02:00 to 03:00. A 15:00 lease still ends at 20:00 local.
        var cap = Lease.HardCap(Local(2026, 3, 29, 15), Workday);
        Assert.That(cap, Is.EqualTo(Local(2026, 3, 29, 20)));
        Assert.That(cap.Offset, Is.EqualTo(TimeSpan.FromHours(2)));
    }

    [Test]
    public void Ends_at_the_hard_cap_and_stays_ended()
    {
        var start = Local(2026, 11, 17, 14);
        var lease = Lease.Begin("L", start, Workday);
        var cap = Local(2026, 11, 17, 20);
        for (var t = start; t < cap; t = t.AddMinutes(10))
            lease.Heartbeat(t);

        Assert.That(lease.Evaluate(cap), Is.EqualTo(LeaseEnd.HardCap));
        Assert.That(lease.Heartbeat(cap.AddMinutes(1)), Is.False);
        Assert.That(lease.Evaluate(cap.AddMinutes(1)), Is.EqualTo(LeaseEnd.HardCap));
    }

    [Test]
    public void Ends_when_heartbeats_stop()
    {
        var start = Local(2026, 11, 17, 9);
        var lease = Lease.Begin("L", start, Workday);
        Assert.That(lease.Evaluate(start.AddMinutes(15)), Is.EqualTo(LeaseEnd.None));
        Assert.That(lease.Evaluate(start.AddMinutes(16)), Is.EqualTo(LeaseEnd.HeartbeatLost));
    }

    [Test]
    public void A_heartbeat_after_loss_does_not_revive_the_lease()
    {
        var start = Local(2026, 11, 17, 9);
        var lease = Lease.Begin("L", start, Workday);
        Assert.That(lease.Heartbeat(start.AddMinutes(30)), Is.False);
        Assert.That(lease.Evaluate(start.AddMinutes(30)), Is.EqualTo(LeaseEnd.HeartbeatLost));
    }

    [Test]
    public void Revoke_ends_the_lease_and_its_elevations()
    {
        var start = Local(2026, 11, 17, 9);
        var lease = Lease.Begin("L", start, Workday);
        lease.Elevate("llm", "admin", TimeSpan.FromMinutes(15), start);
        lease.Revoke();
        Assert.That(lease.Evaluate(start.AddMinutes(1)), Is.EqualTo(LeaseEnd.Revoked));
        Assert.That(lease.ActiveElevations("llm", start.AddMinutes(1)), Is.Empty);
    }

    [Test]
    public void Elevation_is_time_boxed_and_scoped_to_its_service()
    {
        var start = Local(2026, 11, 17, 9);
        var lease = Lease.Begin("L", start, Workday);
        lease.Elevate("llm", "admin", TimeSpan.FromMinutes(15), start);

        Assert.That(lease.ActiveElevations("llm", start.AddMinutes(14)), Is.EquivalentTo(new[] { "admin" }));
        Assert.That(lease.ActiveElevations("ravendb", start.AddMinutes(14)), Is.Empty);
        lease.Heartbeat(start.AddMinutes(14));
        Assert.That(lease.ActiveElevations("llm", start.AddMinutes(15)), Is.Empty);
    }

    [Test]
    public void Elevation_never_outlives_the_lease()
    {
        var start = Local(2026, 11, 17, 19, 50);
        var lease = Lease.Begin("L", start, Workday);
        Assert.That(lease.Elevate("llm", "admin", TimeSpan.FromHours(1), start), Is.EqualTo(Local(2026, 11, 17, 20)));
    }

    [Test]
    public void Elevation_on_an_ended_lease_is_refused()
    {
        var start = Local(2026, 11, 17, 9);
        var lease = Lease.Begin("L", start, Workday);
        lease.Revoke();
        Assert.That(lease.Elevate("llm", "admin", TimeSpan.FromMinutes(5), start), Is.Null);
    }
}
