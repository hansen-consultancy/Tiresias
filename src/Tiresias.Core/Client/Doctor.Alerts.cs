using Tiresias.Alerts;

namespace Tiresias.Client;

/// <summary>The Alerts card on the app's About page, to fix, test or remove a sink.</summary>
public sealed record ReviewAlerts(string SinkId) : DoctorFix
{
    public override string Instruction => $"in the Tiresias app: About, Alerts: fix or remove {SinkId}, then Send a test alert";
}

public static partial class Doctor
{
    public const string AlertsKind = "alert sinks that aren't delivering";

    /// <summary>
    /// A finding per sink whose alerts aren't arriving (docs/alerts.md, <i>Delivery</i>). Names the sink by
    /// its id only, never its address or credential. Gone once the sink delivers again or is removed or fixed.
    /// </summary>
    public static IEnumerable<DoctorCheck> FailingAlerts(IEnumerable<FailingSink> failing) =>
        failing.Select(f => new DoctorCheck($"alerts to {f.Id} aren't arriving", DoctorStatus.Fail,
            f.Stopped
                ? "the receiver refused them, so Tiresias stopped sending to it. Fix its address or credential on the About page's Alerts card; "
                  + "a test alert that gets through starts it again"
                : $"none has gone through for {SinkHealth.FailingAfter.TotalMinutes:0} minutes or more; Tiresias keeps trying. "
                  + "Check the receiver, then send a test alert from the About page's Alerts card",
            new ReviewAlerts(f.Id), Kind: AlertsKind, Subject: f.Stopped ? "stopped" : "failing"));
}
