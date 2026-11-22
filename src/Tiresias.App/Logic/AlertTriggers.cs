using Tiresias.Alerts;
using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Which of the app's own moments alert (docs/alerts.md, <i>Events</i>); the mapping to a subject is <see cref="AlertSources"/>'.</summary>
public static class AlertTriggers
{
    /// <summary>
    /// A consent request at the gate: refused by the blocklist or the lockdown, or shown while the
    /// Windows session is locked, so nobody can be at the dialog. A request asked as usual, with
    /// someone at the machine, is <c>consent.asked</c> and doesn't alert: you are at the dialog.
    /// </summary>
    public static AlertKind? Consent(GateDecision decision, bool sessionLocked) => decision switch
    {
        GateDecision.Blocked => AlertKind.ProgramBlocked,
        GateDecision.LockedDown => AlertKind.LockdownRefused,
        _ when sessionLocked => AlertKind.ConsentWhileLocked,
        _ => null,
    };

    /// <summary>
    /// The Windows session after a session switch: locked, logged off or disconnected (nobody can see
    /// a dialog) until it is unlocked, logged on or connected again, locally or remotely.
    /// </summary>
    /// <param name="reason">The <c>SessionSwitchReason</c>, by name, so this stays free of Windows types.</param>
    public static bool SessionLocked(bool wasLocked, string reason) => reason switch
    {
        "SessionLock" or "SessionLogoff" or "ConsoleDisconnect" or "RemoteDisconnect" => true,
        "SessionUnlock" or "SessionLogon" or "ConsoleConnect" or "RemoteConnect" => false,
        _ => wasLocked,
    };

    /// <summary>
    /// <c>findings.new</c> for a background check run: the open findings Home hasn't shown and that no
    /// earlier run of this app already alerted on, as one event. <see cref="FindingRun.Alerted"/> is
    /// what to pass next time: keys of findings no longer open drop out, so one that comes back alerts again.
    /// </summary>
    public static FindingRun Findings(IReadOnlyList<DoctorCheck> checks, Dismissals dismissals, IReadOnlySet<string> seen,
        IReadOnlySet<string> alerted, DateTimeOffset at)
    {
        var open = checks.Where(c => c.IsFinding && c.Status != DoctorStatus.Ok && dismissals.For(c) is null)
            .GroupBy(Dismissals.KeyOf).ToDictionary(g => g.Key, g => g.First());
        var fresh = open.Where(f => !seen.Contains(f.Key) && !alerted.Contains(f.Key)).ToList();
        var next = alerted.Where(open.ContainsKey).Concat(fresh.Select(f => f.Key)).ToHashSet();
        return new(AlertSources.FindingsNew([.. fresh.Select(f => f.Value)], at), next);
    }
}

/// <param name="Alert">The event to raise, or <c>null</c> when nothing is new.</param>
/// <param name="Alerted">The keys alerted on so far that are still open.</param>
public sealed record FindingRun(AlertEvent? Alert, IReadOnlySet<string> Alerted);
