using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Decoys;

namespace Tiresias.Tests;

public class DecoyReadTests
{
    const uint Break = 1000;
    const int Opener = 40, Bystander = 50;
    static readonly DateTimeOffset Started = new(2026, 11, 21, 8, 0, 0, TimeSpan.Zero);
    static readonly DateTimeOffset Now = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);

    static ThreadRow Waiting(int pid, int tid, uint since, uint switches = 7) =>
        new(pid, tid, OpenerNaming.Waiting, OpenerNaming.Executive, since, switches);

    static ThreadSnapshot Snapshot(params ThreadRow[] threads) =>
        new(threads, threads.Select(t => t.ProcessId).Distinct().ToDictionary(pid => pid, pid => new ProcessRow(pid, $"p{pid}.exe", Started)));

    /// <summary>Two settle snapshots with the same threads, then the threads still waiting after the release.</summary>
    static DecoyOpener Name(ThreadRow[] settled, params ThreadRow[] afterRelease) =>
        OpenerNaming.Name(Break, [Snapshot(settled), Snapshot(settled)], Snapshot(afterRelease));

    [Test]
    public void The_one_process_whose_stuck_thread_woke_is_named()
    {
        var bystander = Waiting(Bystander, 2, Break);

        Assert.That(Name([Waiting(Opener, 1, Break - 1), bystander], bystander), Is.EqualTo(new DecoyOpener.Named(Opener, "p40.exe", Started)));
    }

    [Test]
    public void Threads_of_two_processes_waking_is_cant_tell() =>
        Assert.That(Name([Waiting(Opener, 1, Break), Waiting(Bystander, 2, Break + 1)]), Is.EqualTo(DecoyOpener.Unknown));

    [Test]
    public void Two_threads_of_one_process_waking_name_it() =>
        Assert.That(Name([Waiting(Opener, 1, Break), Waiting(Opener, 2, Break)]), Is.InstanceOf<DecoyOpener.Named>());

    [Test]
    public void Nothing_woke_is_cant_tell()
    {
        var stuck = Waiting(Opener, 1, Break);

        Assert.That(Name([stuck], stuck), Is.EqualTo(DecoyOpener.Unknown));
        Assert.That(Name([]), Is.EqualTo(DecoyOpener.Unknown));
    }

    [Test]
    public void A_busy_thread_that_switched_while_the_break_was_held_is_no_candidate()
    {
        var busy = Waiting(Bystander, 2, Break, switches: 7);
        var settle = new[] { Snapshot(Waiting(Opener, 1, Break), busy), Snapshot(Waiting(Opener, 1, Break), busy with { ContextSwitches = 8 }) };

        Assert.That(OpenerNaming.Stuck(Break, settle).Select(t => t.ProcessId), Is.EqualTo(new[] { Opener }));
        Assert.That(OpenerNaming.Name(Break, settle, Snapshot()), Is.EqualTo(new DecoyOpener.Named(Opener, "p40.exe", Started)));
    }

    [Test]
    public void A_thread_that_began_a_new_wait_while_the_break_was_held_is_no_candidate()
    {
        var settle = new[] { Snapshot(Waiting(Bystander, 2, Break)), Snapshot(Waiting(Bystander, 2, Break + 1)) };

        Assert.That(OpenerNaming.Stuck(Break, settle), Is.Empty);
    }

    [TestCase(Break - 4, false)]
    [TestCase(Break - 3, true)]
    [TestCase(Break + 2, true)]
    [TestCase(Break + 3, false)]
    public void Only_a_wait_that_began_near_the_break_is_a_candidate(uint since, bool candidate) =>
        Assert.That(OpenerNaming.Stuck(Break, [Snapshot(Waiting(Opener, 1, since))]), candidate ? Has.Count.EqualTo(1) : Is.Empty);

    [Test]
    public void The_window_holds_across_the_tick_counter_wrapping() =>
        Assert.That(OpenerNaming.Stuck(1, [Snapshot(Waiting(Opener, 1, uint.MaxValue))]), Has.Count.EqualTo(1));

    [Test]
    public void Only_threads_waiting_as_an_open_does_are_candidates()
    {
        var running = new ThreadRow(Opener, 1, 2, OpenerNaming.Executive, Break, 7);
        var sleeping = new ThreadRow(Opener, 2, OpenerNaming.Waiting, 6, Break, 7);
        var system = Waiting(4, 3, Break);

        Assert.That(OpenerNaming.Stuck(Break, [Snapshot(running, sleeping, system)]), Is.Empty);
    }

    static readonly RoutineFolders Folders = new(@"C:\Windows", [@"C:\Program Files", @"C:\Program Files (x86)"], @"C:\ProgramData",
        @"C:\Users\alice\AppData\Local", @"C:\Users\alice\AppData\Local\Programs\Tiresias\");

    [TestCase(@"C:\Windows\System32\SearchProtocolHost.exe", "Windows Search")]
    [TestCase(@"c:\windows\system32\searchindexer.exe", "Windows Search")]
    [TestCase(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MsMpEng.exe", "Microsoft Defender")]
    [TestCase(@"C:\Program Files\Windows Defender\MpDefenderCoreService.exe", "Microsoft Defender")]
    [TestCase(@"C:\Windows\explorer.exe", "File Explorer")]
    [TestCase(@"C:\Windows\System32\prevhost.exe", "File Explorer")]
    [TestCase(@"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "OneDrive")]
    [TestCase(@"C:\Program Files\Microsoft OneDrive\OneDrive.Sync.Service.exe", "OneDrive")]
    [TestCase(@"C:\Users\alice\AppData\Local\Programs\Tiresias\tir.exe", "Tiresias")]
    public void A_known_opener_in_its_own_place_is_routine(string image, string label) =>
        Assert.That(DecoyReads.RoutineOpener(image, Folders), Is.EqualTo(label));

    [TestCase(@"C:\Users\alice\Downloads\explorer.exe")]
    [TestCase(@"C:\Users\alice\AppData\Local\Temp\MsMpEng.exe")]
    [TestCase(@"C:\Users\alice\AppData\Local\OneDrive.exe")]
    [TestCase(@"C:\ProgramData\Evil\MsMpEng.exe")]
    [TestCase(@"C:\Windows\..\Users\alice\explorer.exe")]
    [TestCase(@"C:\Windows\System32\cmd.exe")]
    [TestCase(@"C:\WindowsApps\explorer.exe")]
    [TestCase("explorer.exe")]
    [TestCase(null)]
    public void Anything_else_is_not_routine(string? image) =>
        Assert.That(DecoyReads.RoutineOpener(image, Folders), Is.Null);

    [Test]
    public void A_read_says_opened_and_is_told_from_a_use() => Assert.Multiple(() =>
    {
        Assert.That(DecoyReads.What(@"C:\Users\alice\Documents\passwords.txt"), Is.EqualTo("opened the decoy file passwords.txt"));
        Assert.That(new DecoyUseRecord(null, "opened the decoy file .env", Now).IsRead, Is.True);
        Assert.That(new DecoyUseRecord(null, "the decoy API key", Now).IsRead, Is.False);
    });

    [Test]
    public void The_watched_files_are_every_placed_decoy_file()
    {
        var set = DecoySet.Mint(_ => true)
            .With(new(DecoyKind.PasswordsFile, @"C:\Users\alice\Documents\passwords.txt", Now))
            .With(new(DecoyKind.Project, @"C:\Users\alice\source\billing-api-old", Now))
            .With(new(DecoyKind.Variables, "user environment", Now));

        Assert.That(DecoyPlan.Files(set), Is.EqualTo(new[]
        {
            @"C:\Users\alice\Documents\passwords.txt",
            Path.Combine(@"C:\Users\alice\source\billing-api-old", "appsettings.Production.json"),
            Path.Combine(@"C:\Users\alice\source\billing-api-old", ".env"),
        }));
    }

    [Test]
    public void Repeated_reads_are_one_per_program_and_file_a_minute()
    {
        var filter = new DecoyHitFilter();
        DecoyHit Read(string file, double seconds) => new(DecoyUse.Read, file, 12, "x.exe", Now.AddSeconds(seconds));

        Assert.That(filter.ShouldReport(Read("a.txt", 0)), Is.True);
        Assert.That(filter.ShouldReport(Read("a.txt", 10)), Is.False);
        Assert.That(filter.ShouldReport(Read(".env", 10)), Is.True);
    }

    const string Reader = @"C:\Users\alice\AppData\Local\Temp\agent.exe";

    static string Line(string? process, string what, DateTimeOffset at, string? reason = null) =>
        System.Text.Json.JsonSerializer.Serialize(new { time = at, kind = "Deny", consumer = "decoy", service = what, path = @"C:\x\passwords.txt", process, reason });

    [Test]
    public void Reads_are_parsed_and_routine_ones_skipped()
    {
        var uses = Doctor.DecoyUses([
            Line($"{Reader} (pid 12)", "opened the decoy file passwords.txt", Now, "x opened it; started by unknown"),
            Line(@"C:\Windows\System32\SearchProtocolHost.exe (pid 13)", "opened the decoy file passwords.txt", Now,
                $"{DecoyReads.RoutineReason} (Windows Search): it opened the decoy file passwords.txt"),
            Line(null, "opened the decoy file .env", Now),
        ]).ToArray();

        Assert.That(uses, Is.EqualTo(new[]
        {
            new DecoyUseRecord(Reader, "opened the decoy file passwords.txt", Now),
            new DecoyUseRecord(null, "opened the decoy file .env", Now),
        }));
    }

    [Test]
    public void A_read_is_a_warning_per_program_that_blocks_nothing()
    {
        var findings = Doctor.Decoys([
            new(Reader, "opened the decoy file passwords.txt", Now.AddHours(-1)),
            new(Reader, "opened the decoy file .env", Now),
            new("MsMpEng.exe", "opened the decoy file .env", Now),
        ], [], Now).ToArray();

        Assert.That(findings, Has.Length.EqualTo(2));
        Assert.That(findings.Select(f => f.Status), Is.All.EqualTo(DoctorStatus.Warn));
        Assert.That(findings.Select(f => f.Kind), Is.All.EqualTo(Doctor.DecoyReadKind));
        Assert.That(findings[0].Name, Is.EqualTo("agent.exe opened a decoy file"));
        Assert.That(findings[0].Detail, Does.Contain($"{Reader} opened the decoy file .env").And.Contain("2 times").And.Not.Contain("stole"));
        Assert.That(findings[0].Fix, Is.EqualTo(new RevealFile(Reader)));
        Assert.That(FindingView.Button(findings[0].Fix)?.Action, Is.EqualTo(FixAction.RevealFile));
        // Known only by its file name: nothing to show in Explorer.
        Assert.That(findings[1].Fix, Is.Null);
    }

    [Test]
    public void A_read_is_never_a_use()
    {
        var findings = Doctor.Decoys([new(Reader, "opened the decoy file passwords.txt", Now)], [Reader], Now).ToArray();

        Assert.That(findings.Single().Kind, Is.EqualTo(Doctor.DecoyReadKind));
        Assert.That(findings.Single().Fix, Is.Not.InstanceOf<UnblockProgram>());
    }

    [Test]
    public void A_program_blocked_for_a_use_gets_no_second_finding_for_its_reads()
    {
        var findings = Doctor.Decoys([new(Reader, "the decoy API key", Now), new(Reader, "opened the decoy file .env", Now)], [Reader], Now).ToArray();

        Assert.That(findings.Single().Kind, Is.EqualTo(Doctor.DecoyKind));
    }

    [Test]
    public void Reads_that_could_not_be_named_are_one_warning_for_thirty_days() => Assert.Multiple(() =>
    {
        var many = Doctor.Decoys([new(null, "opened the decoy file .env", Now.AddDays(-2)), new(null, "opened the decoy file passwords.txt", Now.AddDays(-1))], [], Now).Single();
        Assert.That(many.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(many.Kind, Is.EqualTo(Doctor.DecoyReadKind));
        Assert.That(many.Detail, Does.Contain("opened the decoy file passwords.txt").And.Contain("2 times"));
        Assert.That(Doctor.Decoys([new(null, "opened the decoy file .env", Now.AddDays(-31))], [], Now), Is.Empty);
        Assert.That(Doctor.Decoys([new(Reader, "opened the decoy file .env", Now.AddDays(-31))], [], Now), Is.Empty);
    });
}
