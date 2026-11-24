using Tiresias.Audit;
using Tiresias.Client;
using Tiresias.Decoys;
using Tiresias.Trust;

namespace Tiresias.Alerts;

/// <summary>
/// Turns what a source reports into an <see cref="AlertEvent"/> (docs/alerts.md, <i>Events</i>): names
/// and paths only, never a value, a token or a command line. Each mapping takes only the fields it
/// may pass on, so what it is not handed can't leave.
/// </summary>
public static class AlertSources
{
    /// <summary>
    /// <c>decoy.used</c> for a decoy credential used; <c>null</c> for a decoy file read, which is
    /// <see cref="DecoyRead"/>'s. The endpoint is left out: it can carry what the program sent.
    /// </summary>
    /// <param name="parents">The processes that started it, nearest first.</param>
    /// <param name="what">Which decoy, in the activity log's words (<c>DecoyTouch.What</c>).</param>
    public static AlertEvent? DecoyUsed(DecoyHit hit, IReadOnlyList<string> parents, string what) =>
        hit.Use == DecoyUse.Read ? null
            : new(AlertKind.DecoyUsed, new AlertSubject(Program: hit.Program, ProcessId: hit.ProcessId, Parents: parents, What: what), hit.At);

    /// <summary>
    /// <c>decoy.read</c> for a decoy file opened by a program that isn't a routine opener (an
    /// indexer, an antivirus): the same programs the app notifies of. <c>null</c> for anything else.
    /// </summary>
    /// <param name="routine">Why the opener is routine, or <c>null</c> when it isn't (<c>DecoyTouch.Routine</c>).</param>
    public static AlertEvent? DecoyRead(DecoyHit hit, IReadOnlyList<string> parents, string what, string? routine) =>
        hit.Use != DecoyUse.Read || routine is not null ? null
            : new(AlertKind.DecoyRead, new AlertSubject(Program: hit.Program, ProcessId: hit.ProcessId, Parents: parents, What: what), hit.At);

    /// <summary>
    /// A consent request the app refused or couldn't put in front of anyone: <c>program.blocked</c>,
    /// <c>lockdown.refused</c>, <c>consent.while-locked</c> or <c>incident.reported</c>.
    /// </summary>
    /// <param name="names">The secret or variable names asked for; never the request's heading, command line or other text.</param>
    /// <param name="parents">The processes that started it, nearest first.</param>
    public static AlertEvent Asked(AlertKind kind, string? program, int? processId, IReadOnlyList<string>? names, IReadOnlyList<string>? parents, DateTimeOffset at)
    {
        if (kind != AlertKind.ProgramBlocked && kind != AlertKind.LockdownRefused && kind != AlertKind.ConsentWhileLocked && kind != AlertKind.IncidentReported)
            throw new ArgumentException($"{kind.Event} isn't about a consent request.", nameof(kind));
        return new(kind, new AlertSubject(Program: program, ProcessId: processId, Parents: parents, Names: names), at);
    }

    /// <summary>
    /// The solo broker's audit records that alert: <c>trust.rejected</c>, <c>trust.break-glass</c>,
    /// <c>vault.rolled-back</c>, <c>vault.unapproved</c> and <c>approval.invalid</c>; <c>null</c> for
    /// every other record. The record's <c>Reason</c> is free text and never passed on whole: only the
    /// secret's name a vault refusal starts with, or the failure kind a rejected chain starts with.
    /// </summary>
    public static AlertEvent? Audited(AuditRecord record, DateTimeOffset at) => record switch
    {
        { Kind: AuditKind.TrustRejected } => new(AlertKind.TrustRejected, new AlertSubject(What: FailureKind(record.Reason)), at),
        { Kind: AuditKind.BreakGlass } => new(AlertKind.TrustBreakGlass, AlertSubject.None, at),
        { Kind: AuditKind.Deny, Reason: { } reason } when Slug(reason, "secret-rolled-back: ") is { } slug =>
            new(AlertKind.VaultRolledBack, new AlertSubject(Names: [slug]), at),
        { Kind: AuditKind.Deny, Reason: { } reason } when Slug(reason, "policy-not-approved: ") is { } slug =>
            new(AlertKind.VaultUnapproved, new AlertSubject(Names: [slug]), at),
        { Kind: AuditKind.Deny, Reason: "approval-invalid" } =>
            new(AlertKind.ApprovalInvalid, new AlertSubject(Program: record.Process, Service: record.Service), at),
        _ => null,
    };

    /// <summary>
    /// <c>findings.new</c> for findings that just appeared: a warning when any of them fails, info when
    /// they only warn, <c>null</c> when there are none. One event for the whole batch, naming each
    /// finding by its title, never its detail.
    /// </summary>
    public static AlertEvent? FindingsNew(IReadOnlyCollection<DoctorCheck> found, DateTimeOffset at)
    {
        var shown = found.Where(c => c.Status != DoctorStatus.Ok).ToList();
        if (shown.Count == 0)
            return null;
        var kind = shown.Any(c => c.Status == DoctorStatus.Fail) ? AlertKind.FindingsFailing : AlertKind.FindingsWarning;
        return new(kind, new AlertSubject(Findings: [.. shown.Select(c => c.Name).Distinct().Order(StringComparer.Ordinal)]), at);
    }

    /// <summary><c>alerts.failing</c> about <paramref name="sink"/>, for the other sinks: its id only, which a public sink doesn't get.</summary>
    public static AlertEvent AlertsFailing(FailingSink sink, DateTimeOffset at) => new(AlertKind.AlertsFailing, new AlertSubject(Sink: sink.Id), at);

    /// <summary>The secret name after <paramref name="prefix"/>, up to the <c>;</c> that ends it.</summary>
    static string? Slug(string reason, string prefix)
    {
        if (!reason.StartsWith(prefix, StringComparison.Ordinal))
            return null;
        var rest = reason[prefix.Length..];
        var end = rest.IndexOf(';', StringComparison.Ordinal);
        var slug = (end < 0 ? rest : rest[..end]).Trim();
        return slug.Length > 0 ? slug : null;
    }

    /// <summary>The verifier's failure kind a rejection starts with (<c>Rollback at seq 4: …</c>), or <c>null</c> when it starts with anything else.</summary>
    static string? FailureKind(string? reason) =>
        Enum.TryParse<TrustFailureKind>(reason?.Split(' ', 2)[0], ignoreCase: false, out var kind) && Enum.IsDefined(kind) ? kind.ToString() : null;
}
