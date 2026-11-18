using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class BlocklistTests
{
    const string Evil = @"C:\Users\alice\AppData\Local\Temp\evil.exe";
    const string Web = @"C:\src\web\bin\web.exe";
    static readonly DateTimeOffset Now = new(2026, 11, 18, 21, 0, 0, TimeSpan.Zero);

    static string? NoFile(string _) => null;

    static Func<string, string?> Hashes(params (string Path, string Sha)[] files) =>
        path => files.FirstOrDefault(f => f.Path == path).Sha;

    [Test]
    public void An_empty_list_asks_without_reading_any_file()
    {
        var read = false;

        var decision = Blocklist.Empty.Decide(Web, _ => { read = true; return "aa"; });

        Assert.That(decision, Is.EqualTo(GateDecision.Ask));
        Assert.That(read, Is.False);
    }

    [Test]
    public void This_wasnt_me_locks_down_and_refuses_every_program()
    {
        var list = Blocklist.Empty.Escalate(Evil, "aa", Now);

        Assert.That(list.Decide(Web, NoFile), Is.EqualTo(GateDecision.LockedDown));
        Assert.That(list.Decide(null, NoFile), Is.EqualTo(GateDecision.LockedDown));
    }

    [Test]
    public void After_an_unlock_only_the_blocked_program_is_refused()
    {
        var list = Blocklist.Empty.Escalate(Evil, "aa", Now).Unlocked();

        Assert.That(list.Decide(Evil, NoFile), Is.EqualTo(GateDecision.Blocked));
        Assert.That(list.Decide(Evil.ToUpperInvariant(), NoFile), Is.EqualTo(GateDecision.Blocked));
        Assert.That(list.Decide(Web, Hashes((Web, "bb"))), Is.EqualTo(GateDecision.Ask));
        Assert.That(list.Decide(null, NoFile), Is.EqualTo(GateDecision.Ask));
    }

    [Test]
    public void A_copy_of_a_blocked_file_elsewhere_is_blocked_by_its_hash()
    {
        var list = Blocklist.Empty.Escalate(Evil, "AA", Now).Unlocked();

        Assert.That(list.Decide(@"C:\Users\alice\Downloads\renamed.exe", Hashes((@"C:\Users\alice\Downloads\renamed.exe", "aa"))),
            Is.EqualTo(GateDecision.Blocked));
    }

    [Test]
    public void A_program_whose_file_could_not_be_hashed_is_still_blocked_by_path()
    {
        var list = Blocklist.Empty.Escalate(Evil, null, Now).Unlocked();
        var read = false;

        Assert.That(list.Decide(Evil, NoFile), Is.EqualTo(GateDecision.Blocked));
        Assert.That(list.Decide(Web, _ => { read = true; return null; }), Is.EqualTo(GateDecision.Ask));
        Assert.That(read, Is.False, "no blocked hash to compare with");
    }

    [TestCase(null)]
    [TestCase("pid 4242")]
    [TestCase("evil.exe")]
    public void A_program_without_a_full_path_locks_down_but_blocks_nothing(string? program)
    {
        var list = Blocklist.Empty.Escalate(program, null, Now);

        Assert.That(list.LockedDown, Is.True);
        Assert.That(list.Programs, Is.Empty);
    }

    [Test]
    public void Blocking_the_same_path_again_keeps_one_entry_with_the_new_hash()
    {
        var list = Blocklist.Empty.Escalate(Evil, "aa", Now).Escalate(Evil.ToUpperInvariant(), "bb", Now.AddHours(1));

        Assert.That(list.Programs, Has.Count.EqualTo(1));
        Assert.That(list.Programs[0].Sha256, Is.EqualTo("bb"));
    }

    [Test]
    public void Unblocking_lets_the_program_ask_again()
    {
        var list = Blocklist.Empty.Escalate(Evil, "aa", Now).Escalate(Web, "bb", Now).Unlocked().Unblock(Evil);

        Assert.That(list.Decide(Evil, NoFile), Is.EqualTo(GateDecision.Ask));
        Assert.That(list.Decide(Web, NoFile), Is.EqualTo(GateDecision.Blocked));
    }

    [Test]
    public void The_file_round_trips()
    {
        var list = Blocklist.Empty.Escalate(Evil, "aa", Now);

        var read = Blocklist.Parse(list.ToJson());

        Assert.That(read.LockedDown, Is.True);
        Assert.That(read.Programs, Is.EqualTo(list.Programs));
    }

    [Test]
    public void No_file_is_an_empty_list()
    {
        var read = Blocklist.Parse(null);

        Assert.That(read.LockedDown, Is.False);
        Assert.That(read.Programs, Is.Empty);
    }

    [TestCase("{ not json")]
    [TestCase("""{ "v": 2, "lockedDown": false, "programs": [] }""")]
    [TestCase("null")]
    public void A_damaged_or_newer_file_fails_closed(string json)
    {
        var read = Blocklist.Parse(json);

        Assert.That(read.LockedDown, Is.True);
        Assert.That(read.Decide(Web, NoFile), Is.EqualTo(GateDecision.LockedDown));
    }
}
