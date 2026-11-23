using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class HyperVTests
{
    static ReachFacts Facts(HyperVAccess access) => new([], [], access);

    static DoctorCheck[] Checks(HyperVAccess access, HyperVContents? contents, bool asked = true) =>
        [.. Doctor.HyperVContents(Facts(access), asked ? new ReachContents(null, HyperV: contents) : null)];

    [TestCase(@"C:\VMs\dev.vhdx", HyperVFileKind.Disk)]
    [TestCase(@"C:\VMs\old.VHD", HyperVFileKind.Disk)]
    [TestCase(@"C:\VMs\dev_1A2B.avhdx", HyperVFileKind.Checkpoint)]
    [TestCase(@"C:\VMs\x.vmrs", HyperVFileKind.Memory)]
    [TestCase(@"C:\VMs\x.vmgs", HyperVFileKind.Memory)]
    [TestCase(@"C:\VMs\x.bin", HyperVFileKind.Memory)]
    [TestCase(@"C:\VMs\x.vmcx", null)]
    [TestCase(@"C:\VMs\notes.txt", null)]
    public void Kinds(string path, HyperVFileKind? kind) => Assert.That(HyperVScan.Kind(path), Is.EqualTo(kind));

    [Test]
    public void A_readable_vm_file_is_a_finding()
    {
        var contents = new HyperVContents(null,
        [
            new(@"C:\Users\Public\Documents\Hyper-V\Virtual Hard Disks\dev.vhdx", HyperVFileKind.Disk, ["Users"]),
            new(@"C:\VMs\dev\x.vmrs", HyperVFileKind.Memory, [Doctor.YourAccount], Vm: "dev"),
            new(@"C:\VMs\locked.vhdx", HyperVFileKind.Disk, []),
        ]);
        var checks = Checks(HyperVAccess.AdminPromptAway, contents);

        Assert.That(checks.Select(c => c.Name), Is.EqualTo(new[] { "hyper-v file dev.vhdx", "hyper-v file x.vmrs" }));
        Assert.That(checks[0].Detail, Is.EqualTo(@"C:\Users\Public\Documents\Hyper-V\Virtual Hard Disks\dev.vhdx, a VM disk, is readable for Users: any program you run can copy it and read the guest's files offline, without Hyper-V"));
        Assert.That(checks[1].Detail, Does.StartWith(@"C:\VMs\dev\x.vmrs, a saved state of dev, is readable for your account").And.Contain("the guest's memory"));
        Assert.That(checks.All(c => c.Status == DoctorStatus.Warn && c.Fix == new ReachGuide(ReachTopic.HyperVFiles)));
        Assert.That(checks[0].Fix!.Instruction, Does.StartWith("as an administrator, move the VM's files"));
    }

    [Test]
    public void Dismissing_one_file_leaves_another_of_the_same_name()
    {
        var contents = new HyperVContents(null,
        [
            new(@"C:\VMs\a\dev.vhdx", HyperVFileKind.Disk, ["Users"]),
            new(@"C:\VMs\b\dev.vhdx", HyperVFileKind.Disk, ["Users"]),
        ]);
        var checks = Checks(HyperVAccess.None, contents);
        Assert.That(Dismissals.KeyOf(checks[0]), Is.Not.EqualTo(Dismissals.KeyOf(checks[1])));
    }

    [Test]
    public void Members_see_the_vms_the_group_opens()
    {
        var check = Checks(HyperVAccess.Member, new(["build", "dev"], [new(@"C:\VMs\dev.vhdx", HyperVFileKind.Disk, [], "dev")])).Single();
        Assert.That(check.Detail, Is.EqualTo("looked at 1 VM file: none readable without Hyper-V Administrators; Hyper-V Administrators opens 2 VMs: build, dev"));
    }

    [Test]
    public void Nothing_found_left_out_and_not_asked()
    {
        Assert.That(Checks(HyperVAccess.None, new(null, [], LeftOut: 3)).Single().Detail,
            Is.EqualTo("looked at 0 VM files: none readable without Hyper-V Administrators; 3 more were not looked at"));
        Assert.That(Checks(HyperVAccess.None, null, asked: false).Single().Detail, Does.StartWith("not looked at: tir doctor --reach"));
        Assert.That(Checks(HyperVAccess.NotInstalled, null, asked: false), Is.Empty);
        Assert.That(Checks(HyperVAccess.NotInstalled, new(null, [])), Is.Empty);
    }

    [Test]
    public void A_look_counts_when_hyper_v_was_looked_at() =>
        Assert.That(ReachLook.Counts(new(null, HyperV: new(null, []))), Is.True);
}
