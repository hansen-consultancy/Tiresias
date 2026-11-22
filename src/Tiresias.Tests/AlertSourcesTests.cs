using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Audit;
using Tiresias.Client;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Tests;

/// <summary>
/// Phase 5 of docs/alerts.md: each source's mapping to an <see cref="AlertEvent"/>, which moments alert
/// (and that a plain <c>consent.asked</c> doesn't), and a canary per source through every sink's bytes.
/// </summary>
public class AlertSourcesTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly byte[] InstallKey = [.. Enumerable.Range(1, 32).Select(i => (byte)i)];

    // ---- Decoy read ----

    [Test]
    public void A_decoy_file_read_by_a_program_that_isnt_routine_is_decoy_read()
    {
        var hit = new DecoyHit(DecoyUse.Read, "C:\\Users\\alice\\passwords.txt", 42, "C:\\x.exe", T0);
        var e = AlertSources.DecoyRead(hit, ["cmd.exe (7)"], "the decoy passwords file", routine: null)!;
        Assert.That((e.Kind, e.At), Is.EqualTo((AlertKind.DecoyRead, T0)));
        Assert.That(e.Subject, Is.EqualTo(new AlertSubject(Program: "C:\\x.exe", ProcessId: 42, Parents: e.Subject.Parents, What: "the decoy passwords file")));
        Assert.That(e.Subject.Parents, Is.EqualTo(new[] { "cmd.exe (7)" }));
    }

    [Test]
    public void A_routine_opener_or_a_credential_use_is_not_decoy_read()
    {
        Assert.That(AlertSources.DecoyRead(new(DecoyUse.Read, "C:\\d.txt", 1, "C:\\indexer.exe", T0), [], "the decoy file", "Windows Search"), Is.Null);
        Assert.That(AlertSources.DecoyRead(new(DecoyUse.AdminToken, "http://127.0.0.1:5999/", 1, "C:\\x.exe", T0), [], "the decoy admin token", null), Is.Null);
    }

    // ---- Consent requests ----

    [TestCase(GateDecision.Blocked, false, "program.blocked")]
    [TestCase(GateDecision.Blocked, true, "program.blocked")]
    [TestCase(GateDecision.LockedDown, false, "lockdown.refused")]
    [TestCase(GateDecision.LockedDown, true, "lockdown.refused")]
    [TestCase(GateDecision.Ask, true, "consent.while-locked")]
    public void A_refused_request_or_one_nobody_can_see_alerts(GateDecision decision, bool locked, string alertEvent) =>
        Assert.That(AlertTriggers.Consent(decision, locked)!.Event, Is.EqualTo(alertEvent));

    [Test]
    public void A_plain_consent_asked_doesnt_alert() =>
        Assert.That(AlertTriggers.Consent(GateDecision.Ask, sessionLocked: false), Is.Null);

    [TestCase(false, "SessionLock", true)]
    [TestCase(false, "SessionLogoff", true)]
    [TestCase(false, "ConsoleDisconnect", true)]
    [TestCase(false, "RemoteDisconnect", true)]
    [TestCase(true, "SessionUnlock", false)]
    [TestCase(true, "SessionLogon", false)]
    [TestCase(true, "ConsoleConnect", false)]
    [TestCase(true, "RemoteConnect", false)]
    [TestCase(true, "SessionRemoteControl", true)]
    [TestCase(false, "SessionRemoteControl", false)]
    public void The_session_is_locked_from_a_lock_or_disconnect_until_an_unlock_or_connect(bool was, string reason, bool locked) =>
        Assert.That(AlertTriggers.SessionLocked(was, reason), Is.EqualTo(locked));

    [Test]
    public void A_consent_alert_carries_the_program_its_parents_and_the_names()
    {
        var e = AlertSources.Asked(AlertKind.ProgramBlocked, "C:\\x.exe", 42, ["ConnectionStrings:Db"], ["cmd.exe (7)"], T0);
        Assert.That((e.Kind, e.Subject.Program, e.Subject.ProcessId, e.Subject.Names, e.Subject.Parents, e.Subject.What),
            Is.EqualTo((AlertKind.ProgramBlocked, "C:\\x.exe", (int?)42, (IReadOnlyList<string>)["ConnectionStrings:Db"], (IReadOnlyList<string>)["cmd.exe (7)"], (string?)null)));
    }

    [Test]
    public void Only_consent_kinds_map_from_a_consent_request() =>
        Assert.That(() => AlertSources.Asked(AlertKind.DecoyUsed, "C:\\x.exe", 1, null, null, T0), Throws.ArgumentException);

    // ---- Broker audit ----

    [Test]
    public void A_rejected_chain_names_the_failure_kind_only()
    {
        var e = AlertSources.Audited(new(AuditKind.TrustRejected, Consumer: "laptop", Reason: "Rollback at seq 4: chain shorter than head 9"), T0)!;
        Assert.That((e.Kind, e.Subject, e.At), Is.EqualTo((AlertKind.TrustRejected, new AlertSubject(What: "Rollback"), T0)));
        Assert.That(AlertSources.Audited(new(AuditKind.TrustRejected, Reason: "something else"), T0)!.Subject, Is.EqualTo(AlertSubject.None));
    }

    [Test]
    public void A_paper_key_use_is_break_glass_with_no_subject() =>
        Assert.That(AlertSources.Audited(new(AuditKind.BreakGlass, Consumer: "laptop", Reason: "paper key 'paper-1' of 'alice' signed seq 3"), T0),
            Is.EqualTo(new AlertEvent(AlertKind.TrustBreakGlass, AlertSubject.None, T0)));

    [Test]
    public void A_vault_refusal_names_the_secret()
    {
        var rolledBack = AlertSources.Audited(new(AuditKind.Deny, "lease-1", Reason: "secret-rolled-back: github-pat; vault reload refused"), T0)!;
        var unapproved = AlertSources.Audited(new(AuditKind.Deny, "lease-1", Reason: "policy-not-approved: sql-prod; vault reload refused"), T0)!;
        Assert.That((rolledBack.Kind, rolledBack.Subject.Names), Is.EqualTo((AlertKind.VaultRolledBack, (IReadOnlyList<string>)["github-pat"])));
        Assert.That((unapproved.Kind, unapproved.Subject.Names), Is.EqualTo((AlertKind.VaultUnapproved, (IReadOnlyList<string>)["sql-prod"])));
    }

    [Test]
    public void An_invalid_approval_names_the_service_and_the_process()
    {
        var e = AlertSources.Audited(new(AuditKind.Deny, "lease-1", "laptop", "github", "admin", "GET", "/repos", 401, "approval-invalid", "abcd1234", "C:\\x.exe (pid 42)"), T0)!;
        Assert.That((e.Kind, e.Subject), Is.EqualTo((AlertKind.ApprovalInvalid, new AlertSubject(Program: "C:\\x.exe (pid 42)", Service: "github"))));
    }

    static IEnumerable<AuditRecord> Quiet()
    {
        yield return new(AuditKind.Allow, "lease-1", "laptop", "github");
        yield return new(AuditKind.Mint, "lease-1", "laptop", "github");
        yield return new(AuditKind.Deny, "lease-1", "laptop", "github", Status: 403, Reason: "elevation-required: admin");
        yield return new(AuditKind.Deny, "lease-1", "laptop", "github", Status: 503, Reason: "no-lease");
        yield return new(AuditKind.Deny, Reason: "secret-rolled-back: ");
        yield return new(AuditKind.TrustLink, Consumer: "laptop", Reason: "seq 4 add-device");
        yield return new(AuditKind.PlaceholderRevoked, "lease-1", Reason: "policy-changed");
        yield return new(AuditKind.LeaseBegin, "lease-1");
    }

    [TestCaseSource(nameof(Quiet))]
    public void Every_other_audit_record_is_quiet(AuditRecord record) =>
        Assert.That(AlertSources.Audited(record, T0), Is.Null);

    // ---- Findings ----

    static DoctorCheck Finding(string name, DoctorStatus status, string detail = "detail") => new(name, status, detail, new ReviewUserSecrets(name));

    [Test]
    public void New_findings_are_a_warning_when_one_fails_and_info_when_they_only_warn()
    {
        var failing = AlertSources.FindingsNew([Finding("b", DoctorStatus.Warn), Finding("a", DoctorStatus.Fail)], T0)!;
        var warning = AlertSources.FindingsNew([Finding("b", DoctorStatus.Warn)], T0)!;
        Assert.That((failing.Kind, failing.Kind.Severity, failing.Subject.Findings), Is.EqualTo((AlertKind.FindingsFailing, AlertSeverity.Warning, (IReadOnlyList<string>)["a", "b"])));
        Assert.That((warning.Kind, warning.Kind.Severity), Is.EqualTo((AlertKind.FindingsWarning, AlertSeverity.Info)));
        Assert.That(AlertSources.FindingsNew([], T0), Is.Null);
        Assert.That(AlertSources.FindingsNew([Finding("listed only", DoctorStatus.Ok)], T0), Is.Null);
    }

    [Test]
    public void A_check_run_alerts_once_per_finding_home_hasnt_shown()
    {
        var a = Finding("a", DoctorStatus.Fail);
        var b = Finding("b", DoctorStatus.Warn);
        var shown = Finding("shown", DoctorStatus.Fail);
        var seen = new HashSet<string> { Dismissals.KeyOf(shown) };

        var first = AlertTriggers.Findings([a, b, shown, new("not a finding", DoctorStatus.Fail, "x")], Dismissals.Empty, seen, new HashSet<string>(), T0);
        Assert.That(first.Alert!.Subject.Findings, Is.EqualTo(new[] { "a", "b" }));

        var again = AlertTriggers.Findings([a, b, shown], Dismissals.Empty, seen, first.Alerted, T0);
        Assert.That(again.Alert, Is.Null, "already alerted, still unseen");

        var dismissed = Dismissals.Empty.Dismiss(b, "fine", T0);
        var gone = AlertTriggers.Findings([a], dismissed, seen, again.Alerted, T0);
        var back = AlertTriggers.Findings([a, b], Dismissals.Empty, seen, gone.Alerted, T0);
        Assert.That(back.Alert!.Subject.Findings, Is.EqualTo(new[] { "b" }), "a finding that went away and came back alerts again");
        Assert.That(back.Alert.Kind, Is.EqualTo(AlertKind.FindingsWarning));
    }

    // ---- Canary per source, through the planner and every sink's bytes ----

    const string Value = "CANARY-value";
    const string Token = "CANARY-token";
    const string ProgramPath = "C:\\Users\\alice\\CANARY-1\\CANARY-5.exe";

    /// <summary>
    /// Each source's event, built from inputs that carry the secret value and a placeholder token beside
    /// the names: in the endpoint, a free-text reason, a finding's detail. A consent request's value and
    /// token would be in its heading or command line, which <see cref="AlertSources.Asked"/> doesn't take.
    /// </summary>
    static IEnumerable<(string Name, AlertEvent Event)> Sources()
    {
        string[] parents = ["CANARY-2.exe (7)", "CANARY-3.exe (8)"];
        yield return ("decoy.read", AlertSources.DecoyRead(new(DecoyUse.Read, $"C:\\decoys\\{Value}.txt:{Token}", 4242, ProgramPath, T0), parents, "CANARY-4", null)!);
        foreach (var kind in new[] { AlertKind.ProgramBlocked, AlertKind.LockdownRefused, AlertKind.ConsentWhileLocked, AlertKind.IncidentReported })
            yield return (kind.Event, AlertSources.Asked(kind, ProgramPath, 4242, ["CANARY-6", "CANARY-7"], parents, T0));
        yield return ("trust.rejected", AlertSources.Audited(new(AuditKind.TrustRejected, Consumer: Value, Reason: $"Fork at seq 4: {Value} {Token}", Token: Token), T0)!);
        yield return ("trust.break-glass", AlertSources.Audited(new(AuditKind.BreakGlass, Consumer: Value, Reason: $"paper key '{Value}' of '{Token}' signed seq 3"), T0)!);
        yield return ("vault.rolled-back", AlertSources.Audited(new(AuditKind.Deny, Value, Reason: $"secret-rolled-back: CANARY-6; {Value} {Token}", Token: Token), T0)!);
        yield return ("vault.unapproved", AlertSources.Audited(new(AuditKind.Deny, Value, Reason: $"policy-not-approved: CANARY-6; {Value} {Token}", Token: Token), T0)!);
        yield return ("approval.invalid", AlertSources.Audited(new(AuditKind.Deny, Value, Value, "CANARY-6", Value, "POST", $"/{Value}", 401, "approval-invalid", Token,
            $"{ProgramPath} (pid 4242)", Value), T0)!);
        yield return ("findings.new", AlertSources.FindingsNew([new("CANARY-6", DoctorStatus.Fail, $"{Value} {Token}", new ReviewUserSecrets(Value), Subject: Token)], T0)!);
    }

    static IEnumerable<TestCaseData> SourcesBySink() =>
        Sources().SelectMany(c => new[] { AlertRedaction.Public, AlertRedaction.Trusted }
            .Select(r => new TestCaseData(c.Event, r).SetArgDisplayNames(c.Name, r.ToString())));

    [TestCaseSource(nameof(SourcesBySink))]
    public async Task No_value_or_token_leaves_and_names_only_in_a_trusted_detail(AlertEvent alert, AlertRedaction redaction)
    {
        var handler = FakeHandler.Always(HttpStatusCode.OK);
        await using var hub = AlertLcdHubTests.FakeHub.Start();
        var log = new ConcurrentQueue<string>();
        var time = TimeProvider.System;
        await using var center = new AlertCenter(new HttpAlertTransport(handler, time), time, log.Enqueue, new LcdHubLink(time, log.Enqueue, hub.PipeName));
        center.Start();
        center.Use(new("workstation", InstallKey,
        [
            new WebhookSink("siem", new("https://hooks.example.com/t"), [new("Authorization", "Bearer sink-credential")], AlertSeverity.Info, redaction),
            new NtfySink("phone", new("https://ntfy.example.com/topic"), "tk_sink-credential", AlertSeverity.Info, redaction),
            new LcdHubSink("desk", AlertSeverity.Info, redaction),
        ]), null);
        center.Raise(alert);
        await Until(() => handler.Requests.Count == 2 && hub.Statuses.Count == 1);

        var webhook = handler.Requests.Single(r => r.Url.Host == "hooks.example.com");
        var ntfy = handler.Requests.Single(r => r.Url.Host == "ntfy.example.com");
        var hubBytes = Encoding.UTF8.GetString(hub.Raw);
        foreach (var wire in new[] { $"POST {webhook.Url}\n{webhook.Wire}", $"POST {ntfy.Url}\n{ntfy.Wire}", hubBytes })
            Assert.That(wire, Does.Not.Contain(Value).And.Not.Contain(Token));
        Assert.That(log, Has.All.Not.Contains("CANARY"));
        Assert.That(hubBytes, Does.Not.Contain("CANARY"), "LcdHub never shows detail");

        var json = JsonNode.Parse(webhook.Body)!.AsObject();
        var detail = json["detail"]?.ToJsonString() ?? "";
        json.Remove("detail");
        Assert.That(json.ToJsonString() + webhook.Url, Does.Not.Contain("CANARY").And.Not.Contain("alice").And.Not.Contain("4242"));
        var ntfyCanaries = Canaries($"{ntfy.Url}\n{ntfy.Wire}");
        if (redaction == AlertRedaction.Public)
        {
            Assert.That(detail, Is.Empty);
            Assert.That(ntfyCanaries, Is.Empty);
        }
        else
        {
            Assert.That(Canaries(detail), Is.EquivalentTo(Canaries(Names(alert.Subject))), "every name the subject holds, in detail");
            Assert.That(ntfyCanaries, Is.SubsetOf(new[] { "CANARY-5" }), "a trusted ntfy body gets the program's file name only");
        }
    }

    static string[] Canaries(string text) => [.. Regex.Matches(text, "CANARY-\\d").Select(m => m.Value).Distinct()];

    static string Names(AlertSubject s) =>
        string.Join('\n', new[] { s.Program, s.What, s.Service }.Concat(s.Parents ?? []).Concat(s.Names ?? []).Concat(s.Findings ?? []).Where(x => x is not null));

    static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 1000 && !condition(); i++)
            await Task.Delay(10);
        Assert.That(condition(), Is.True, "timed out");
    }
}
