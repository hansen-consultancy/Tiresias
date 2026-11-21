using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class DecoyFindingTests
{
    const string Evil = @"C:\Users\alice\AppData\Local\Temp\evil.exe";
    static readonly DateTimeOffset Now = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);

    static string Line(string? process, string what, DateTimeOffset at) =>
        System.Text.Json.JsonSerializer.Serialize(new { time = at, kind = "Deny", consumer = "decoy", service = what, path = "SQL Server", process });

    [Test]
    public void Decoy_uses_are_read_from_the_activity_log_and_other_lines_skipped()
    {
        var uses = Doctor.DecoyUses([
            Line($"{Evil} (pid 12)", "the decoy SQL password", Now),
            Line("unknown image (pid 13)", "a decoy endpoint", Now),
            """{"time":"2026-11-21T09:00:00Z","kind":"Allow","consumer":"environment","service":"x"}""",
            "not json",
        ]).ToArray();

        Assert.That(uses, Is.EqualTo(new[] { new DecoyUseRecord(Evil, "the decoy SQL password", Now), new DecoyUseRecord(null, "a decoy endpoint", Now) }));
    }

    [Test]
    public void A_blocked_program_that_used_a_decoy_is_one_finding_with_unblock()
    {
        var findings = Doctor.Decoys([new(Evil, "the decoy admin token", Now.AddHours(-1)), new(Evil, "the decoy API key", Now)], [Evil], Now).ToArray();

        Assert.That(findings, Has.Length.EqualTo(1));
        Assert.That(findings[0].Status, Is.EqualTo(DoctorStatus.Fail));
        Assert.That(findings[0].Detail, Does.Contain("the decoy API key").And.Contain("2 times"));
        Assert.That(findings[0].Fix, Is.EqualTo(new UnblockProgram(Evil)));
        Assert.That(FindingView.Button(findings[0].Fix), Is.EqualTo((FixAction.Unblock, "Finding_FixUnblock")));
    }

    [Test]
    public void An_unblocked_program_is_no_longer_a_finding() =>
        Assert.That(Doctor.Decoys([new(Evil, "the decoy API key", Now)], [], Now), Is.Empty);

    [Test]
    public void An_unnamed_use_is_a_warning_for_thirty_days() => Assert.Multiple(() =>
    {
        Assert.That(Doctor.Decoys([new(null, "a decoy endpoint", Now.AddDays(-2))], [], Now).Single().Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(Doctor.Decoys([new(null, "a decoy endpoint", Now.AddDays(-31))], [], Now), Is.Empty);
        var many = Doctor.Decoys([new(null, "a decoy endpoint", Now.AddDays(-2)), new(null, "the decoy API key", Now.AddDays(-1))], [], Now).Single();
        Assert.That(many.Detail, Does.Contain("the decoy API key").And.Contain("2 times"));
        Assert.That(many.Subject, Is.EqualTo(Now.AddDays(-1).ToString("O")));
    });

    [Test]
    public void A_decoy_blocks_the_program_without_a_lockdown()
    {
        var list = Blocklist.Empty.Block(Evil, "aa", Now);

        Assert.That(list.LockedDown, Is.False);
        Assert.That(list.Decide(Evil, _ => null), Is.EqualTo(GateDecision.Blocked));
        Assert.That(list.Block(Evil, "bb", Now).Programs, Has.Count.EqualTo(1));
        Assert.That(Blocklist.Empty.Block(null, null, Now), Is.EqualTo(Blocklist.Empty));
        Assert.That(Blocklist.Empty.Block("pid 12", null, Now).Programs, Is.Empty);
    }
}
