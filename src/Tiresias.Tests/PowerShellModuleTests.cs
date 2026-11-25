using NUnit.Framework;
using Tiresias.Client;

namespace Tiresias.Tests;

public class PowerShellModuleTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 25, 10, 0, 0, TimeSpan.Zero);
    static readonly ExtensionHost PowerShell = new("PowerShell", "pwsh.exe", null, "Uninstall-PSResource or Uninstall-Module");

    static string Info(string source, string version = "2.1.0", string updated = """<Nil N="UpdatedDate" />""") => $$"""
        <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
          <Obj RefId="0">
            <TN RefId="0"><T>Microsoft.PowerShell.Commands.PSRepositoryItemInfo</T></TN>
            <MS>
              <S N="Name">AcmeTools</S>
              <S N="Version">{{version}}</S>
              <S N="Author">Acme</S>
              <S N="RepositorySourceLocation">{{source}}</S>
              <S N="Repository">PSGallery</S>
              <DT N="InstalledDate">2026-03-04T22:25:58.816835+01:00</DT>
              {{updated}}
              <Obj N="Dependencies" RefId="1"><MS><S N="Version">9.9.9</S></MS></Obj>
            </MS>
          </Obj>
        </Objs>
        """;

    [Test]
    public void One_from_the_gallery_names_it_as_publisher()
    {
        var module = Doctor.PowerShellModule(PowerShell, "AcmeTools", "2.1.0", Info("https://www.powershellgallery.com/api/v2"), Now);

        Assert.That(module, Is.EqualTo(new InstalledExtension(PowerShell, "AcmeTools", "2.1.0", "PowerShell Gallery", new DateTimeOffset(2026, 3, 4, 22, 25, 58, TimeSpan.FromHours(1)).AddTicks(8168350))));
    }

    [Test]
    public void Its_last_update_wins_over_its_install()
    {
        var module = Doctor.PowerShellModule(PowerShell, "AcmeTools", "2.1.0",
            Info("https://www.powershellgallery.com/api/v2", updated: """<DT N="UpdatedDate">2026-10-01T08:00:00+00:00</DT>"""), Now);

        Assert.That(module?.Updated, Is.EqualTo(new DateTimeOffset(2026, 10, 1, 8, 0, 0, TimeSpan.Zero)));
    }

    [TestCase("https://packages.example.com/api/v2")]
    [TestCase("http://www.powershellgallery.com/api/v2")]
    [TestCase("C:\\feeds\\local")]
    public void One_from_another_repository_has_an_unknown_publisher_whatever_its_name(string source) =>
        Assert.That(Doctor.PowerShellModule(PowerShell, "AcmeTools", "2.1.0", Info(source), Now)?.Publisher, Is.Null);

    [Test]
    public void One_copied_in_by_hand_has_its_folder_version_and_time()
    {
        var module = Doctor.PowerShellModule(PowerShell, "AcmeTools", "1.0", null, Now);

        Assert.That(module, Is.EqualTo(new InstalledExtension(PowerShell, "AcmeTools", "1.0", null, Now)));
    }

    [TestCase("not xml")]
    [TestCase("<!DOCTYPE Objs [<!ENTITY e \"x\">]><Objs xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj><MS><S N=\"Version\">&e;</S></MS></Obj></Objs>")]
    public void Damaged_install_info_is_ignored(string info) =>
        Assert.That(Doctor.PowerShellModule(PowerShell, "AcmeTools", "1.0", info, Now), Is.EqualTo(new InstalledExtension(PowerShell, "AcmeTools", "1.0", null, Now)));

    [TestCase("")]
    [TestCase("..")]
    [TestCase("-x")]
    public void An_odd_folder_is_no_module(string name) =>
        Assert.That(Doctor.PowerShellModule(PowerShell, name, null, null, Now), Is.Null);

    [Test]
    public void The_newest_version_folder_is_compared_as_a_version()
    {
        Assert.That(Doctor.NewestModuleVersion(["1.9.0", "1.10.0", "en-US", "1.2"]), Is.EqualTo("1.10.0"));
        Assert.That(Doctor.NewestModuleVersion(["en-US", "Public"]), Is.Null);
    }

    [Test]
    public void A_module_without_a_publisher_in_a_shell_that_used_a_credential_says_how_to_remove_it()
    {
        var module = Doctor.PowerShellModule(PowerShell, "AcmeTools", "1.0", null, Now)!;

        var finding = Doctor.AttackSurface([module], [], [new(@"C:\Program Files\PowerShell\7\pwsh.exe", "github", Now.AddDays(-1))], [], Now).Single();

        Assert.That(finding.Name, Is.EqualTo("AcmeTools in PowerShell (unknown publisher)"));
        Assert.That(finding.Fix!.Instruction, Is.EqualTo("remove AcmeTools in PowerShell, Uninstall-PSResource or Uninstall-Module"));
    }
}
