using Tiresias.AdminTier;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AdminFreezeTests
{
    const string Alice = "S-1-5-21-1000-1000-1000-1001";
    const string Bob = "S-1-5-21-1000-1000-1000-1002";
    const string Evil = @"C:\Users\alice\AppData\Local\Temp\evil.exe";

    static readonly DateTime T0 = new(2026, 11, 21, 9, 0, 0, DateTimeKind.Utc);
    static readonly FreezeFolders Folders = new(@"C:\Windows", [@"C:\Program Files\Tiresias", @"C:\Users\alice\AppData\Local\TiresiasApp"]);

    static FreezeCandidate P(int pid, int parent, int minutes, string image = Evil, string? owner = Alice, bool critical = false) =>
        new(pid, parent, T0.AddMinutes(minutes), image, owner, critical);

    static string? Refusal(FreezeCandidate p) => AdminFreeze.Refusal(p, Alice, 900, Folders);

    [TestCase(4, Evil, Alice, false, "is the system")]
    [TestCase(900, Evil, Alice, false, "is the admin tier itself")]
    [TestCase(10, Evil, null, false, "can't be read")]
    [TestCase(10, Evil, Bob, false, "isn't the user's")]
    [TestCase(10, Evil, Alice, true, "is critical to Windows")]
    [TestCase(10, @"C:\Windows\explorer.exe", Alice, false, "is part of Windows' session")]
    [TestCase(10, @"C:\Windows\System32\csrss.exe", Alice, false, "is part of Windows' session")]
    [TestCase(10, @"C:\Users\alice\AppData\Local\TiresiasApp\current\Tiresias.exe", Alice, false, "is Tiresias")]
    [TestCase(10, @"C:\Program Files\Tiresias\Admin\tiresias-admin.exe", Alice, false, "is Tiresias")]
    [TestCase(10, Evil, Alice, false, null)]
    [TestCase(10, @"C:\Users\alice\AppData\Local\Temp\explorer.exe", Alice, false, null)]
    [TestCase(10, @"C:\Users\alice\Downloads\Tiresias.exe", Alice, false, null)]
    public void Who_may_never_be_frozen(int pid, string image, string? owner, bool critical, string? refusal) =>
        Assert.That(Refusal(P(pid, 1, 0, image, owner, critical)), Is.EqualTo(refusal));

    [Test]
    public void A_freeze_takes_the_process_and_what_it_started_since()
    {
        var running = new[]
        {
            P(10, 1, 0),
            P(11, 10, 1, @"C:\Users\alice\tools\child.exe"),
            P(12, 11, 2, @"C:\Users\alice\tools\grandchild.exe"),
            // Under a parent id reused since: started before the process that now has that id.
            P(13, 10, -5, @"C:\Users\alice\tools\older.exe"),
            P(14, 1, 0, @"C:\Users\alice\tools\unrelated.exe"),
        };

        var (processes, refusal) = AdminFreeze.Plan(10, running, Alice, 900, Folders, []);

        Assert.That(refusal, Is.Null);
        Assert.That(processes.Select(p => p.ProcessId), Is.EqualTo(new[] { 10, 11, 12 }));
        Assert.That(processes[0], Is.EqualTo(new FrozenProcess(10, T0, Evil)));
    }

    [Test]
    public void A_refused_descendant_is_left_out_but_its_own_children_are_not()
    {
        var running = new[]
        {
            P(10, 1, 0),
            P(11, 10, 1, @"C:\Windows\System32\conhost.exe"),
            P(12, 11, 2, @"C:\Users\alice\tools\child.exe"),
            P(13, 10, 1, owner: Bob),
        };

        Assert.That(AdminFreeze.Plan(10, running, Alice, 900, Folders, []).Processes.Select(p => p.ProcessId), Is.EqualTo(new[] { 10, 12 }));
    }

    [Test]
    public void A_refused_or_gone_process_refuses_the_freeze() => Assert.Multiple(() =>
    {
        Assert.That(AdminFreeze.Plan(10, [P(10, 1, 0, owner: Bob)], Alice, 900, Folders, []).Refusal, Is.EqualTo("isn't the user's"));
        Assert.That(AdminFreeze.Plan(10, [P(10, 1, 0, owner: Bob)], Alice, 900, Folders, []).Processes, Is.Empty);
        Assert.That(AdminFreeze.Plan(10, [P(11, 1, 0)], Alice, 900, Folders, []).Refusal, Is.EqualTo("isn't running"));
    });

    [Test]
    public void A_frozen_process_is_never_frozen_twice()
    {
        var running = new[] { P(10, 1, 0), P(11, 10, 1, @"C:\Users\alice\tools\child.exe") };
        var frozen = new[] { new FrozenProcess(10, T0, Evil) };

        Assert.That(AdminFreeze.Plan(10, running, Alice, 900, Folders, frozen).Processes.Select(p => p.ProcessId), Is.EqualTo(new[] { 11 }));
        Assert.That(AdminFreeze.Plan(10, [P(10, 1, 0)], Alice, 900, Folders, frozen).Refusal, Is.EqualTo(AdminFreeze.AlreadyFrozen));
    }

    [Test]
    public void A_job_name_is_global_and_unguessable()
    {
        var name = AdminFreeze.JobName(Guid.NewGuid());
        Assert.That(name, Does.StartWith(@"Global\Tiresias.Freeze."));
        Assert.That(name, Is.Not.EqualTo(AdminFreeze.JobName(Guid.NewGuid())));
    }

    static AdminFreezeEntry Entry(long id, string user, string program, params ulong[] filters) =>
        new(id, user, program, AdminFreeze.JobName(Guid.NewGuid()), [new((int)id, T0, program)], filters, DateTimeOffset.UnixEpoch);

    [Test]
    public void Thaw_takes_out_the_users_freezes_of_the_program_and_lifts_their_filters()
    {
        var frozen = AdminFrozen.Empty.Add(Entry(1, Alice, Evil, 1, 2, 3, 4)).Add(Entry(2, Alice, Evil)).Add(Entry(3, Alice, @"C:\other.exe", 5));

        var (thawed, lift, left) = frozen.Thaw(Alice, Evil.ToUpperInvariant());

        Assert.That(thawed.Select(e => e.Id), Is.EqualTo(new long[] { 1, 2 }));
        Assert.That(lift, Is.EqualTo(new ulong[] { 1, 2, 3, 4 }));
        Assert.That(left.Entries.Select(e => e.Id), Is.EqualTo(new long[] { 3 }));
        Assert.That(left.NextId, Is.EqualTo(4));
        Assert.That(left.Blocked(Evil), Is.False);
        Assert.That(frozen.Blocked(Evil), Is.True);
    }

    [Test]
    public void Filters_another_users_freeze_still_needs_pass_to_it()
    {
        var frozen = AdminFrozen.Empty.Add(Entry(1, Alice, Evil, 1, 2)).Add(Entry(2, Bob, Evil));

        var (_, lift, left) = frozen.Thaw(Alice, Evil);

        Assert.That(lift, Is.Empty);
        Assert.That(left.Entries.Single().Filters, Is.EqualTo(new ulong[] { 1, 2 }));
        Assert.That(left.Blocked(Evil), Is.True);
        Assert.That(frozen.Thaw(Bob, @"C:\other.exe").Thawed, Is.Empty);
    }

    [Test]
    public void Each_user_counts_only_their_own_freezes()
    {
        var frozen = AdminFrozen.Empty.Add(Entry(1, Alice, Evil)).Add(Entry(2, Bob, Evil));
        Assert.That(frozen.For(Alice.ToLowerInvariant()), Is.EqualTo(1));
        Assert.That(frozen.Processes, Has.Count.EqualTo(2));
    }

    [Test]
    public void The_record_round_trips_and_a_damaged_or_newer_one_refuses()
    {
        var frozen = AdminFrozen.Empty.Add(Entry(1, Alice, Evil, ulong.MaxValue));
        var back = AdminFrozen.Parse(frozen.ToJson())!;

        Assert.Multiple(() =>
        {
            Assert.That(back.NextId, Is.EqualTo(2));
            Assert.That(back.Entries.Single().Filters, Is.EqualTo(new[] { ulong.MaxValue }));
            Assert.That(back.Entries.Single().Processes, Is.EqualTo(frozen.Entries.Single().Processes));
            Assert.That(back.Entries.Single().Job, Is.EqualTo(frozen.Entries.Single().Job));
            Assert.That(AdminFrozen.Parse(null), Is.SameAs(AdminFrozen.Empty));
            Assert.That(AdminFrozen.Parse("not json"), Is.Null);
            Assert.That(AdminFrozen.Parse(frozen.ToJson().Replace("\"v\":1", "\"v\":2", StringComparison.Ordinal)), Is.Null);
            Assert.That(AdminFrozen.Parse(frozen.ToJson().Replace("\"nextId\":2", "\"nextId\":1", StringComparison.Ordinal)), Is.Null);
        });
    }

    [Test]
    public void A_frozen_use_travels_on_the_event()
    {
        var hit = new DecoyHit(DecoyUse.AdminToken, "127.0.0.1:8080", 10, Evil, DateTimeOffset.UnixEpoch);
        var (queue, added) = AdminEventQueue.Empty.Add(hit, [], frozen: true);

        Assert.That(added.Frozen, Is.True);
        Assert.That(AdminEventQueue.Parse(queue.ToJson()).Pending.Single().Frozen, Is.True);
        var wire = AdminWire.FromNode<AdminEvents>(AdminWire.ToNode(new AdminEvents(queue.Pending)));
        Assert.That(wire!.Events.Single().Frozen, Is.True);
    }

    [Test]
    public void The_status_counts_the_callers_freezes() =>
        Assert.That(AdminWire.FromNode<AdminFeatures>(AdminWire.ToNode(new AdminFeatures(Frozen: 2)))!.Frozen, Is.EqualTo(2));

    [Test]
    public void A_frozen_use_reads_back_from_the_activity_log_and_its_finding_offers_thaw()
    {
        var line = System.Text.Json.JsonSerializer.Serialize(new
        {
            time = DateTimeOffset.UnixEpoch, kind = "Deny", consumer = "decoy", service = "the decoy API key", process = $"{Evil} (pid 12)",
            reason = $"used; {Doctor.FrozenNote}",
        });
        var uses = Doctor.DecoyUses([line]).ToArray();

        Assert.That(uses.Single().Frozen, Is.True);
        var finding = Doctor.Decoys(uses, [Evil], DateTimeOffset.UnixEpoch).Single();
        Assert.That(finding.Fix, Is.EqualTo(new ThawProgram(Evil)));
        Assert.That(finding.Detail, Does.Contain("froze"));
        Assert.That(FindingView.Button(finding.Fix), Is.EqualTo((FixAction.Thaw, "Finding_FixThaw")));
    }
}
