using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>
/// One row of the event table (docs/alerts.md, <i>Events</i>): the event's name, severity and the title
/// a sink shows. The title is fixed here so no event's own data ever becomes text on a sink.
/// </summary>
public sealed record AlertKind(string Event, AlertSeverity Severity, string Title)
{
    public static readonly AlertKind DecoyUsed = new("decoy.used", AlertSeverity.Critical, "Decoy credential used");
    public static readonly AlertKind DecoyRead = new("decoy.read", AlertSeverity.Critical, "Decoy file read");
    public static readonly AlertKind TrustRejected = new("trust.rejected", AlertSeverity.Critical, "Trust chain rejected");
    public static readonly AlertKind VaultRolledBack = new("vault.rolled-back", AlertSeverity.Critical, "Vault rolled back");
    public static readonly AlertKind TrustBreakGlass = new("trust.break-glass", AlertSeverity.High, "Paper key used");
    public static readonly AlertKind VaultUnapproved = new("vault.unapproved", AlertSeverity.High, "Vault changed without approval");
    public static readonly AlertKind ApprovalInvalid = new("approval.invalid", AlertSeverity.High, "Unapproved broker request");
    public static readonly AlertKind ProgramBlocked = new("program.blocked", AlertSeverity.High, "Blocked program asked again");
    public static readonly AlertKind LockdownRefused = new("lockdown.refused", AlertSeverity.High, "Request refused in lockdown");
    public static readonly AlertKind IncidentReported = new("incident.reported", AlertSeverity.High, "\"This wasn't me\"");
    public static readonly AlertKind ConsentWhileLocked = new("consent.while-locked", AlertSeverity.High, "Secret requested while locked");
    public static readonly AlertKind FindingsFailing = new("findings.new", AlertSeverity.Warning, "New findings");
    public static readonly AlertKind FindingsWarning = new("findings.new", AlertSeverity.Info, "New findings");
    public static readonly AlertKind AlertsFailing = new("alerts.failing", AlertSeverity.Warning, "Alerts to a sink are failing");
    public static readonly AlertKind AlertsSuppressed = new("alerts.suppressed", AlertSeverity.Warning, "Alerts held back");
    public static readonly AlertKind AlertsTest = new("alerts.test", AlertSeverity.Info, "Test alert");
    public static readonly AlertKind AlertsAlive = new("alerts.alive", AlertSeverity.Info, "Tiresias is running");

    public static IReadOnlyList<AlertKind> All { get; } =
    [
        DecoyUsed, DecoyRead, TrustRejected, VaultRolledBack, TrustBreakGlass, VaultUnapproved, ApprovalInvalid,
        ProgramBlocked, LockdownRefused, IncidentReported, ConsentWhileLocked, FindingsFailing, FindingsWarning,
        AlertsFailing, AlertsSuppressed, AlertsTest, AlertsAlive,
    ];
}
