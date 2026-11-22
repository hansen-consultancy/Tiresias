using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class ReachTests
{
    const string User = "S-1-5-21-1-2-3-1001", DockerUsers = "S-1-5-21-1-2-3-1005", Users = "S-1-5-32-545", System = "S-1-5-18", Admins = "S-1-5-32-544";
    const int Read = ReachAccess.ReadData, ReadWrite = ReachAccess.ReadData | ReachAccess.WriteData;

    static readonly Dictionary<string, string> Token = new()
    {
        [User] = Doctor.YourAccount,
        [DockerUsers] = "docker-users",
        [Users] = "Users",
    };

    static DoctorCheck[] Checks(ReachFacts facts) => [.. Doctor.Reach(facts)];

    static EnginePipe Pipe(string name, EngineKind kind, params string[] to) => new(name, kind, to);

    [Test]
    public void A_pipe_granted_through_a_group_names_the_group()
    {
        var acl = new AccessFacts(System, [new(System, true, 0x1F01FF), new(Admins, true, 0x1F01FF), new(DockerUsers, true, 0x12019F)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.EqualTo(new[] { "docker-users" }));
    }

    [Test]
    public void A_pipe_granted_to_the_user_and_a_group_names_both()
    {
        var acl = new AccessFacts(System, [new(DockerUsers, true, 0x12019F), new(User, true, 0x12019F)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.EqualTo(new[] { "docker-users", Doctor.YourAccount }));
    }

    [Test]
    public void A_pipe_only_administrators_can_open_grants_nothing()
    {
        // Administrators is deny-only in a filtered token, so it is never among the token's SIDs.
        var acl = new AccessFacts(System, [new(System, true, 0x1F01FF), new(Admins, true, 0x1F01FF)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.Empty);
    }

    [Test]
    public void A_matching_deny_wins_over_an_allow()
    {
        var acl = new AccessFacts(System, [new(User, false, Read), new(DockerUsers, true, 0x12019F)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.Empty);
    }

    [Test]
    public void Read_alone_does_not_open_a_pipe_that_needs_write()
    {
        var acl = new AccessFacts(System, [new(Users, true, Read)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.Empty);
        Assert.That(ReachAccess.GrantedTo(acl, Token, Read), Is.EqualTo(new[] { "Users" }));
    }

    [Test]
    public void Generic_rights_count_as_the_data_rights_they_map_to()
    {
        var acl = new AccessFacts(System, [new(User, true, unchecked((int)0x80000000) | 0x40000000)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.EqualTo(new[] { Doctor.YourAccount }));
    }

    [Test]
    public void An_owner_can_read_a_disk_whose_DACL_says_nothing_of_them_but_not_a_pipe()
    {
        var acl = new AccessFacts(User, [new(System, true, 0x1F01FF)]);
        Assert.That(ReachAccess.GrantedTo(acl, Token, Read, ownerReads: true), Is.EqualTo(new[] { Doctor.YourAccount }));
        Assert.That(ReachAccess.GrantedTo(acl, Token, ReadWrite), Is.Empty);
    }

    [Test]
    public void Nothing_reachable_reports_nothing()
    {
        Assert.That(Checks(ReachFacts.None), Is.Empty);
        Assert.That(Checks(new([Pipe("docker_engine", EngineKind.Current)], [], HyperVAccess.NotInstalled)), Is.Empty, "a pipe nobody in the token may open");
    }

    [Test]
    public void An_open_engine_pipe_is_a_finding_with_steps()
    {
        var check = Checks(new([Pipe("docker_engine", EngineKind.Current, "docker-users")], [], HyperVAccess.NotInstalled)).Single();
        Assert.Multiple(() =>
        {
            Assert.That(check.Name, Is.EqualTo(Doctor.DockerEngineCheck));
            Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
            Assert.That(check.IsFinding);
            Assert.That(check.Now, Is.Null, "the engine changes who can reach a secret, not how it is held");
            Assert.That(check.Detail, Does.Contain("docker-users").And.Contain("every container's environment").And.Not.Contain("SYSTEM"));
            Assert.That(check.Fix!.Instruction, Does.Contain("Remove-LocalGroupMember -Group docker-users"));
            Assert.That(FindingView.Button(check.Fix), Is.EqualTo((FixAction.OpenGuide, "Finding_FixReachGuide")));
        });
    }

    [Test]
    public void A_pipe_that_names_the_user_says_leaving_the_group_is_not_enough()
    {
        var check = Checks(new([Pipe("docker_engine", EngineKind.Current, "docker-users", Doctor.YourAccount)], [], HyperVAccess.NotInstalled)).Single();
        Assert.That(check.Fix!.Instruction, Does.Contain("doesn't close it").And.Not.Contain("Remove-LocalGroupMember"));
    }

    [Test]
    public void Several_open_pipes_are_one_line_and_a_Windows_engine_says_administrator()
    {
        var checks = Checks(new(
            [Pipe("docker_engine", EngineKind.Current, "docker-users"), Pipe("dockerDesktopWindowsEngine", EngineKind.Windows, "docker-users"), Pipe("docker_engine_linux", EngineKind.Linux)],
            [], HyperVAccess.NotInstalled));
        Assert.That(checks, Has.Length.EqualTo(1));
        Assert.That(checks[0].Detail, Does.Contain("docker_engine, dockerDesktopWindowsEngine are open").And.Contain("administrator on this PC").And.Not.Contain("docker_engine_linux"));
    }

    [TestCase(HyperVAccess.Member, DoctorStatus.Warn, true)]
    [TestCase(HyperVAccess.AdminPromptAway, DoctorStatus.Ok, false)]
    [TestCase(HyperVAccess.None, DoctorStatus.Ok, false)]
    public void Hyper_V_membership_is_a_finding_only_when_UAC_does_not_hold_it_back(HyperVAccess access, DoctorStatus status, bool finding)
    {
        var check = Checks(new([], [], access)).Single();
        Assert.Multiple(() =>
        {
            Assert.That(check.Name, Is.EqualTo(Doctor.HyperVCheck));
            Assert.That(check.Status, Is.EqualTo(status));
            Assert.That(check.IsFinding, Is.EqualTo(finding));
        });
        if (finding)
            Assert.That(check.Fix!.Instruction, Does.Contain("S-1-5-32-578").And.Contain("BitLocker"));
    }

    [Test]
    public void Readable_WSL_disks_inform_without_a_finding_and_Docker_s_own_are_left_out()
    {
        var check = Checks(new([],
        [
            new("Ubuntu", @"C:\Users\alice\AppData\Local\wsl\{1}\ext4.vhdx", [Doctor.YourAccount]),
            new("Debian", @"C:\Users\alice\AppData\Local\wsl\{2}\ext4.vhdx", [Doctor.YourAccount]),
            new("docker-desktop", @"C:\Users\alice\AppData\Local\Docker\wsl\main\ext4.vhdx", [Doctor.YourAccount]),
            new("Locked", @"D:\wsl\locked\ext4.vhdx", []),
        ], HyperVAccess.NotInstalled)).Single();
        Assert.Multiple(() =>
        {
            Assert.That(check.Name, Is.EqualTo(Doctor.WslDisksCheck));
            Assert.That(check.Status, Is.EqualTo(DoctorStatus.Ok));
            Assert.That(check.IsFinding, Is.False);
            Assert.That(check.Detail, Does.StartWith("2 distributions' disks are files you own: Ubuntu, Debian.").And.Contain("WSLENV"));
            Assert.That(check.Detail, Does.Not.Contain("docker-desktop").And.Not.Contain("Locked"));
        });
    }

    [Test]
    public void The_probe_s_facts_reach_the_doctor()
    {
        var checks = Doctor.Reach(new([Pipe("docker_engine", EngineKind.Current, "docker-users")], [], HyperVAccess.Member)).Select(c => c.Name);
        Assert.That(checks, Is.EqualTo(new[] { Doctor.DockerEngineCheck, Doctor.HyperVCheck }));
    }
}
