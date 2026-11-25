using NUnit.Framework;
using Tiresias.Client;

namespace Tiresias.Tests;

public class ManagedPcTests
{
    static readonly Management Domain = new("corp.example.com", false, false);

    static readonly StartupEntry UserStartup = new("Mine", StartupEntry.RunKey, @"C:\Users\alice\mine.exe", Signed: false);
    static readonly StartupEntry MachineStartup = new("Agent", StartupEntry.MachineRunKey, @"C:\Program Files\Agent\agent.exe", Signed: false);

    static UninstallEntry Entry(string key, string name) => new(key, name, "1.0", @"C:\gone\uninstall.exe", false, false);

    static readonly UninstallEntry UserEntry = Entry(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Mine", "Mine");
    static readonly UninstallEntry MachineEntry = Entry(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Agent", "Agent");

    [TestCase(null, false, false, false)]
    [TestCase("corp.example.com", false, false, true)]
    [TestCase(null, true, false, true)]
    [TestCase(null, false, true, true)]
    public void A_domain_Entra_ID_or_device_management_makes_a_PC_managed(string? domain, bool entra, bool mdm, bool managed) =>
        Assert.That(new Management(domain, entra, mdm).IsManaged, Is.EqualTo(managed));

    [Test]
    public void Only_a_named_and_enrolled_enrollment_counts()
    {
        Assert.That(Management.Enrolled([("MS DM Server", 1)]), Is.True);
        Assert.That(Management.Enrolled([(null, 1), ("", 1), ("MS DM Server", 0), ("MS DM Server", null)]), Is.False);
        Assert.That(Management.Enrolled([]), Is.False);
    }

    [Test]
    public void On_a_managed_PC_only_what_the_user_installed_is_judged()
    {
        var (startup, installed) = Doctor.Judged(Domain, [UserStartup, MachineStartup], [UserEntry, MachineEntry]);

        Assert.That(startup, Is.EqualTo(new[] { UserStartup }));
        Assert.That(installed, Is.EqualTo(new[] { UserEntry }));
    }

    [Test]
    public void On_an_unmanaged_PC_everything_is_judged()
    {
        var (startup, installed) = Doctor.Judged(Management.None, [UserStartup, MachineStartup], [UserEntry, MachineEntry]);

        Assert.That(startup, Has.Length.EqualTo(2));
        Assert.That(installed, Has.Length.EqualTo(2));
    }

    [Test]
    public void The_managed_line_says_by_what_and_is_no_finding()
    {
        var line = Doctor.Managed(new("corp.example.com", true, false)).Single();

        Assert.That(line.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(line.IsFinding, Is.False);
        Assert.That(line.Detail, Does.StartWith("This PC is joined to the corp.example.com domain and joined to Microsoft Entra ID,"));
        Assert.That(Doctor.Managed(Management.None), Is.Empty);
    }

    [Test]
    public async Task Machine_wide_software_raises_nothing_on_a_managed_PC_but_a_blocked_program_still_does()
    {
        var unmanaged = await Doctor.RunAsync(new Probe(Management.None));
        var managed = await Doctor.RunAsync(new Probe(Domain));

        Assert.That(unmanaged.Any(c => c.Name.Contains("Agent", StringComparison.Ordinal)), Is.True);
        Assert.That(managed.Any(c => c.Name.Contains("Agent", StringComparison.Ordinal)), Is.False);
        Assert.That(managed.Any(c => c.Name.Contains("Mine", StringComparison.Ordinal)), Is.True);
        Assert.That(managed.Any(c => c.Kind == Doctor.BlockedKind), Is.True);
        Assert.That(managed.Any(c => c.Name == Doctor.ManagedCheck), Is.True);
    }

    sealed class Probe(Management management) : IDoctorProbe
    {
        public bool Enrolled => true;
        public bool HasDeviceKey => true;
        public bool RecoveryKeySet => true;
        public IReadOnlyList<string> ExposedVariables => [];
        public Task<int?> BrokerStatusAsync() => Task.FromResult<int?>(401);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(true);
        public IEnumerable<DoctorFile> UserSecretsFiles() => [];
        public IEnumerable<DoctorFile> Projects() => [];
        public IEnumerable<DoctorFile> ConfigFiles() => [];
        public IEnumerable<string> KeyFiles() => [];
        public DoctorVault? Vault => new(2, [], []);
        public Management Management => management;
        public IEnumerable<StartupEntry> StartupEntries() => [UserStartup, MachineStartup];
        public IEnumerable<UninstallEntry> UninstallEntries() => [UserEntry, MachineEntry];
        public IEnumerable<string> BlockedPrograms() => [@"C:\Program Files\Bad\bad.exe"];
    }
}
