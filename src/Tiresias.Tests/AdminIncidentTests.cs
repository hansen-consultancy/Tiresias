using System.Text.Json;
using System.Security.Cryptography;
using Tiresias.Admin;
using Tiresias.AdminTier;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AdminIncidentTests
{
    const string Sid = "S-1-5-21-1000-1000-1000-1001";
    const string Other = "S-1-5-21-1000-1000-1000-1002";
    const string Program = @"C:\Tools\one.exe";
    const string Copy = @"C:\Tools\copy.exe";
    static readonly string Hash = new('a', 64);
    static readonly string Different = new('b', 64);
    string folder = null!;

    [SetUp]
    public void SetUp() => folder = Directory.CreateTempSubdirectory("tir-incidents-").FullName;

    [TearDown]
    public void TearDown() => Directory.Delete(folder, recursive: true);

    static DecoyHit Hit(string? program = Program, DecoyUse use = DecoyUse.AdminToken) =>
        new(use, "/admin", 1234, program, DateTimeOffset.UtcNow);

    [Test]
    public void A_local_process_is_measured_from_its_running_image()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Ignore("Windows process image attribution");
            return;
        }
        var image = Environment.ProcessPath!;
        var hit = Hit(image) with { ProcessId = Environment.ProcessId };
        using var stream = File.OpenRead(image);
        Assert.That(PipeCallerIdentity.ImageDigest(hit), Is.EqualTo(Convert.ToHexString(SHA256.HashData(stream))));
        Assert.That(PipeCallerIdentity.ImageDigest(hit with { Program = Program }), Is.Null);
    }

    [Test]
    public void Management_history_retains_authorized_intent_and_outcome_independently_of_queries_and_refusals()
    {
        var log = new ActionLog(Path.Combine(folder, "actions.jsonl"));
        var elevated = new AdminCaller(Other, 1, Sid, Elevated: true, IsService: false);
        var intent = AdminAction.Of(DateTimeOffset.UtcNow, AdminOps.BlocksUnblock, elevated, 42, Program, "requested", null, Sid);
        log.Append(intent);
        log.Append(intent with { Result = "ok" });
        log.Append(intent with { Op = AdminOps.BlocksList, Result = "ok" });
        log.Append(intent with { ActingFor = null, Result = "refused", Reason = "needs elevation" });
        Assert.That(File.ReadAllLines(Path.Combine(folder, "actions.jsonl")), Has.Length.EqualTo(4));
        var changes = File.ReadAllLines(Path.Combine(folder, "changes.jsonl"));
        Assert.That(changes, Has.Length.EqualTo(2));
        Assert.That(changes[0], Does.Contain("requested").And.Contain(Sid).And.Contain(Other).And.Not.Contain("image"));
        Assert.That(changes[1], Does.Contain("\"result\":\"ok\""));
    }

    [Test]
    public void Each_reader_keeps_its_own_position_and_only_explicit_review_advances_pending_delivery()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        var first = journal.Record(Hit(), ["parent (42)"], Hash);
        var second = journal.Record(Hit(Copy), [], Different);
        Assert.That(journal.Read(long.MaxValue, true).Events, Is.Empty);
        Assert.That(journal.Read(first.Id, true).Events.Single().Id, Is.EqualTo(second.Id));
        Assert.That(journal.Read(0, true).Events.Select(e => e.Id), Is.EqualTo(new[] { first.Id, second.Id }));
        Assert.That(journal.Review(long.MaxValue).ReviewedThrough, Is.EqualTo(second.Id));

        var restarted = new AdminIncidentJournal(folder, Sid);
        Assert.That(restarted.Read(0, true).Events, Is.Empty);
        Assert.That(restarted.Review(0).ReviewedThrough, Is.EqualTo(second.Id));
        var next = restarted.Record(Hit(), [], Hash);
        Assert.That(restarted.Read(0, true).Events.Single().Id, Is.EqualTo(next.Id));
        var history = AdminReply.Ok(restarted.Read(0, false)).ResultAs<AdminEvents>()!;
        Assert.That(history.LastId, Is.EqualTo(next.Id));
        Assert.That(history.Events[0].Parents, Is.EqualTo(first.Parents));
        Assert.That(history.Events[0].Hit, Is.EqualTo(first.Hit));
        Assert.That(new AdminIncidentJournal(folder, Other).Read(0, false).Events, Is.Empty);
    }

    [Test]
    public void A_routine_read_is_kept_and_crosses_the_wire_without_blocking()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        var hit = new DecoyHit(DecoyUse.Read, @"C:\Users\alice\passwords.txt", 4242, @"C:\Windows\explorer.exe", DateTimeOffset.UnixEpoch);
        journal.Record(hit, [], Hash, routine: "File Explorer");

        var back = AdminReply.Ok(new AdminIncidentJournal(folder, Sid).Read(0, false)).ResultAs<AdminEvents>()!.Events.Single();

        Assert.That(back.Routine, Is.EqualTo("File Explorer"), "after a restart, on the wire");
        Assert.That(back.Hit, Is.EqualTo(hit));
        Assert.That(journal.Check(hit.Program, Hash).Blocked, Is.False);
    }

    [Test]
    public void A_frozen_use_is_kept_on_its_incident_and_blocks()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        journal.Record(Hit(), [], Hash, frozen: true);

        var back = AdminReply.Ok(new AdminIncidentJournal(folder, Sid).Read(0, false)).ResultAs<AdminEvents>()!.Events.Single();

        Assert.That(back.Frozen, Is.True);
        Assert.That(journal.Check(Program, Hash).Blocked, Is.True);
    }

    [Test]
    public void A_block_survives_restart_and_only_an_explicit_unblock_changes_its_decision()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        var incident = journal.Record(Hit(), [], Hash);
        journal.Review(incident.Id);
        journal = new(folder, Sid);
        var blocked = new AdminBlockStatus(true, incident.Id);
        Assert.That(journal.Check(Program.ToUpperInvariant(), Different), Is.EqualTo(blocked));
        Assert.That(journal.Check(Copy, Hash.ToUpperInvariant()), Is.EqualTo(blocked));
        Assert.That(journal.Check(Copy, null), Is.EqualTo(blocked));
        Assert.That(journal.Check(null, null), Is.EqualTo(blocked));
        Assert.That(journal.Check(Copy, Different), Is.EqualTo(new AdminBlockStatus(false, 0)));
        Assert.That(journal.List().Programs.Single().Path, Is.EqualTo(Program));
        Assert.That(new AdminIncidentJournal(folder, Other).Check(Program, Hash), Is.EqualTo(new AdminBlockStatus(false, 0)));

        journal.Unblock(Program);
        journal = new(folder, Sid);
        Assert.That(journal.Read(0, false).Events.Single().Id, Is.EqualTo(incident.Id));
        Assert.That(journal.List().Programs, Is.Empty);
        var cleared = new AdminBlockStatus(false, incident.Id);
        Assert.That(journal.Check(Program, Different), Is.EqualTo(cleared));
        Assert.That(journal.Check(Copy, Hash), Is.EqualTo(cleared));
        Assert.That(journal.Check(Copy, null), Is.EqualTo(cleared));
        var later = journal.Record(Hit(), [], Hash);
        Assert.That(journal.Check(Copy, Hash), Is.EqualTo(new AdminBlockStatus(true, later.Id)));
    }

    [Test]
    public void Reads_and_unattributed_incidents_are_visible_without_creating_a_program_block()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        journal.Record(Hit(use: DecoyUse.Read), [], Hash);
        journal.Record(Hit(null), [], null);
        Assert.That(journal.Read(0, true).Events, Has.Count.EqualTo(2));
        Assert.That(journal.List().Programs, Is.Empty);
        var e = journal.Record(Hit(), [], null);
        Assert.That(journal.Check(Program, null), Is.EqualTo(new AdminBlockStatus(true, e.Id)));
    }

    [Test]
    public void A_large_block_list_pages_in_path_order_without_duplicates_or_missing_programs()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        for (var i = AdminIncidentJournal.BlockPageSize; i >= 0; i--)
            journal.Record(Hit($@"C:\Tools\program-{i:D3}.exe"), [], null);
        var first = journal.List();
        Assert.That(first.Programs, Has.Count.EqualTo(AdminIncidentJournal.BlockPageSize));
        Assert.That(first.NextAfter, Is.EqualTo(first.Programs[^1].Path));
        var last = journal.List(first.NextAfter!.ToUpperInvariant());
        Assert.That(last.NextAfter, Is.Null);
        Assert.That(last.Programs.Single().Path, Is.EqualTo($@"C:\Tools\program-{AdminIncidentJournal.BlockPageSize:D3}.exe"));
        Assert.That(first.Programs.Select(p => p.Path), Is.Ordered.Using<string>(StringComparer.OrdinalIgnoreCase));
    }

    [Test]
    public void History_is_paged_without_pruning_older_incidents()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        for (var i = 0; i < AdminIncidentJournal.PageSize + 1; i++)
            journal.Record(Hit(), [], null);
        journal = new(folder, Sid);
        var first = journal.Read(0, false);
        Assert.That(first.Events, Has.Count.EqualTo(AdminIncidentJournal.PageSize));
        Assert.That(first.Events[0].Id, Is.EqualTo(1));
        Assert.That(journal.Read(first.Events[^1].Id, false).Events.Single().Id, Is.EqualTo(first.LastId));
    }

    [Test]
    public void Upgrade_keeps_prior_ids_and_retained_incidents()
    {
        var old = new AdminEvent(4, Hit(), []);
        File.WriteAllText(Path.Combine(folder, Sid + ".json"), JsonSerializer.Serialize(new { v = 1, nextId = 9, pending = new[] { old } },
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var journal = new AdminIncidentJournal(folder, Sid);
        Assert.That(journal.Check(Program, Hash), Is.EqualTo(new AdminBlockStatus(true, old.Id)));
        Assert.That(journal.Record(Hit(), [], Hash).Id, Is.EqualTo(9));
        Assert.That(new AdminIncidentJournal(folder, Sid).Read(0, false).Events.Select(e => e.Id), Is.EqualTo(new[] { 4, 9 }));
    }

    [Test]
    public void An_incomplete_or_unknown_journal_prevents_a_clean_decision()
    {
        var path = Path.Combine(folder, Sid + ".jsonl");
        File.WriteAllText(path, "");
        Assert.Throws<InvalidDataException>(() => new AdminIncidentJournal(folder, Sid));
        File.WriteAllText(path, "{");
        Assert.Throws<InvalidDataException>(() => new AdminIncidentJournal(folder, Sid));
        File.WriteAllText(path, "{\"v\":2,\"kind\":\"new\"}\n");
        Assert.Throws<InvalidDataException>(() => new AdminIncidentJournal(folder, Sid));
    }

    [Test]
    public void A_failed_commit_prevents_subsequent_grants()
    {
        var journal = new AdminIncidentJournal(folder, Sid);
        var incident = journal.Record(Hit(), [], Hash);
        using var busy = File.Open(Path.Combine(folder, Sid + ".jsonl"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.Throws<IOException>(() => journal.Unblock(Program));
        Assert.Throws<IOException>(() => journal.Check(Program, Hash));
        busy.Dispose();
        Assert.That(new AdminIncidentJournal(folder, Sid).Check(Program, Hash), Is.EqualTo(new AdminBlockStatus(true, incident.Id)));
    }
}
