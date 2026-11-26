using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class PackageFixTests
{
    const string UserKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\";
    const string MachineKey = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\";

    static UninstallEntry Entry(string name, string? version = "1.0", string key = UserKey) =>
        new(key + name, name, version, $@"C:\Programs\{name}\uninstall.exe", true, true);

    static readonly (PackageFix?, PackageFix?) None = (null, null);

    [Test]
    public void Winget_list_is_read_by_its_columns()
    {
        const string output = "   - \r   \\ \r"
            + "Name                 Id                 Version      Available\r\n"
            + "--------------------------------------------------------------\r\n"
            + "Acme App             Acme.App           1.2.0        1.3.0\r\n"
            + "Beta Tool 2026.1     Beta.Tool          2026.1       \r\n"
            + "Gamma                Gamma.Gamma        < 4.0\r\n"
            + "\r\n"
            + "2 packages have version numbers that cannot be determined.\r\n";

        Assert.That(Packages.WingetList(output), Is.EqualTo(new WingetPackage[]
        {
            new("Acme App", "Acme.App", "1.2.0", "1.3.0"),
            new("Beta Tool 2026.1", "Beta.Tool", "2026.1"),
            new("Gamma", "Gamma.Gamma", null),
        }));
    }

    [Test]
    public void Without_updates_winget_lists_three_columns()
    {
        const string output = "Name   Id        Version\n------------------------\nAcme   Acme.App  1.0\n";

        Assert.That(Packages.WingetList(output), Is.EqualTo(new WingetPackage[] { new("Acme", "Acme.App", "1.0") }));
    }

    [Test]
    public void A_row_shifted_off_its_columns_is_left_out_rather_than_read_wrong()
    {
        // Wide characters take two columns each, so the row's text is shorter than the header's grid.
        const string output = "Name        Id          Version\n------------------------------\n漢字漢字漢字 Acme.Wide   1.0\nAcme        Acme.App    1.0\n";

        Assert.That(Packages.WingetList(output).Select(p => p.Id), Is.EqualTo(new[] { "Acme.App" }));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("No installed package found matching input criteria.")]
    public void Output_without_a_table_lists_nothing(string? output) => Assert.That(Packages.WingetList(output), Is.Empty);

    [Test]
    public void A_program_is_matched_by_name_and_version_and_only_when_one_fits()
    {
        WingetPackage acme = new("Acme", "Acme.App", "1.0");

        Assert.That(Packages.Of(Entry("acme"), [acme]), Is.EqualTo(acme));
        Assert.That(Packages.Of(Entry("Acme", "2.0"), [acme]), Is.Null);
        Assert.That(Packages.Of(Entry("Acme"), [acme, acme with { Id = "Other.Acme" }]), Is.Null);
    }

    [Test]
    public void Winget_updates_to_the_version_it_offers_and_uninstalls_by_exact_id()
    {
        WingetPackage acme = new("Acme", "Acme.App", "1.0", "1.1");

        Assert.That(Packages.Update(acme, machine: false)?.Instruction, Is.EqualTo("winget upgrade --id Acme.App --exact --version 1.1"));
        Assert.That(Packages.Uninstall(acme, machine: false)?.Instruction, Is.EqualTo("winget uninstall --id Acme.App --exact"));
        Assert.That(Packages.Update(acme with { Available = null }, machine: false), Is.Null);
    }

    [Test]
    public void Machine_wide_software_needs_an_administrator()
    {
        var fix = Packages.Uninstall(new("Acme", "Acme.App", "1.0"), machine: true)!;

        Assert.That(fix.Command.Administrator, Is.True);
        Assert.That(fix.Instruction, Is.EqualTo("winget uninstall --id Acme.App --exact, as an administrator"));
        Assert.That(PackageActions.Ask(fix).Body, Is.EqualTo("Package_UninstallBodyAdmin"));
        Assert.That(PackageActions.Ask(fix with { Command = fix.Command with { Administrator = false } }).Body, Is.EqualTo("Package_UninstallBody"));
    }

    [Test]
    public void Dotnet_tools_update_and_uninstall_through_dotnet_tool()
    {
        GlobalTool tool = new("dotnet", "acme.cli", "1.0.0");

        Assert.That(Packages.Update(tool)?.Instruction, Is.EqualTo("dotnet tool update --global acme.cli"));
        var uninstall = Packages.Uninstall(tool)!;
        Assert.That(uninstall.Instruction, Is.EqualTo("dotnet tool uninstall --global acme.cli"));
        Assert.That(uninstall.Command.Start.Program, Is.EqualTo("dotnet"));
        Assert.That(uninstall.Command.Start.Arguments, Is.EqualTo(new[] { "tool", "uninstall", "--global", "acme.cli" }));
    }

    [Test]
    public void Npm_updates_only_to_a_newer_version_its_registry_named_and_runs_through_cmd()
    {
        GlobalTool tool = new("npm", "@acme/cli", "3.0.0");

        Assert.That(Packages.Update(tool), Is.Null);
        Assert.That(Packages.Update(tool with { Latest = "3.1.0" })?.Instruction, Is.EqualTo("npm install --global @acme/cli@3.1.0"));
        var uninstall = Packages.Uninstall(tool)!;
        Assert.That(uninstall.Instruction, Is.EqualTo("npm uninstall --global @acme/cli"));
        Assert.That(uninstall.Command.Start.Program, Is.EqualTo("cmd.exe"));
        Assert.That(uninstall.Command.Start.Arguments, Is.EqualTo(new[] { "/d", "/c", "npm", "uninstall", "--global", "@acme/cli" }));
    }

    [TestCase("winget", "Acme.App & calc")]
    [TestCase("winget", "--force")]
    [TestCase("dotnet", "acme;calc")]
    [TestCase("npm", "acme&calc")]
    [TestCase("npm", "Acme")]
    [TestCase("pipx", "acme")]
    public void Nothing_is_built_from_an_id_that_isnt_plain_or_for_a_manager_not_handled(string manager, string id)
    {
        if (manager == "winget")
        {
            Assert.That(Packages.Uninstall(new WingetPackage("Acme", id, "1.0", "1.1"), machine: false), Is.Null);
            Assert.That(Packages.Update(new WingetPackage("Acme", id, "1.0", "1.1"), machine: false), Is.Null);
            return;
        }
        Assert.That(Packages.Uninstall(new GlobalTool(manager, id, "1.0", "1.1")), Is.Null);
        Assert.That(Packages.Update(new GlobalTool(manager, id, "1.0", "1.1")), Is.Null);
    }

    [TestCase("1.1 & calc")]
    [TestCase("Unknown")]
    public void No_update_is_built_to_a_version_that_isnt_a_plain_number(string version)
    {
        Assert.That(Packages.Update(new WingetPackage("Acme", "Acme.App", "1.0", version), machine: false), Is.Null);
        Assert.That(Packages.Update(new GlobalTool("npm", "acme", "1.0", version)), Is.Null);
    }

    [Test]
    public void Npm_outdated_names_the_newer_version_of_npm_tools_only()
    {
        const string outdated = """{ "sass": { "current": "1.0.0", "wanted": "1.2.0", "latest": "1.2.0" }, "acme": { "latest": "9.0.0" } }""";
        GlobalTool[] tools = [new("npm", "sass", "1.0.0"), new("npm", "other", "2.0.0"), new("dotnet", "acme", "1.0.0")];

        Assert.That(Packages.WithLatest(tools, outdated), Is.EqualTo(new GlobalTool[]
            { new("npm", "sass", "1.0.0", "1.2.0"), new("npm", "other", "2.0.0"), new("dotnet", "acme", "1.0.0") }));
        Assert.That(Packages.WithLatest(tools, "not json"), Is.EqualTo(tools));
    }

    [Test]
    public void The_installed_page_offers_winget_fixes_except_machine_wide_ones_on_a_managed_pc()
    {
        WingetPackage[] winget = [new("Acme", "Acme.App", "1.0", "1.1")];

        Assert.That(PackageActions.For(Entry("Acme"), winget, managed: true).Uninstall, Is.Not.Null);
        Assert.That(PackageActions.For(Entry("Acme", key: MachineKey), winget, managed: true), Is.EqualTo(None));
        Assert.That(PackageActions.For(Entry("Acme", key: MachineKey), winget, managed: false).Update!.Command.Administrator, Is.True);
        Assert.That(PackageActions.For(Entry("Other"), winget, managed: false), Is.EqualTo(None));
    }

    [Test]
    public void An_update_button_names_the_version_it_moves_to_when_known()
    {
        Assert.That(PackageActions.Target(Packages.Update(new WingetPackage("Acme", "Acme.App", "1.0", "1.1"), false)!), Is.EqualTo("1.1"));
        Assert.That(PackageActions.Target(Packages.Update(new GlobalTool("npm", "@acme/cli", "1.0", "2.0"))!), Is.EqualTo("2.0"));
        var dotnet = Packages.Update(new GlobalTool("dotnet", "acme", "1.0"))!;
        Assert.That(PackageActions.Target(dotnet), Is.Null);
        Assert.That(PackageActions.Ask(dotnet).Button, Is.EqualTo("Package_UpdateNewest"));
    }

    [TestCase(0, "Package_Done", true)]
    [TestCase(1, "Package_Failed", false)]
    [TestCase(null, "Package_NotStarted", false)]
    public void The_outcome_follows_the_managers_exit_code(int? exit, string key, bool done) =>
        Assert.That(PackageActions.Outcome(exit), Is.EqualTo((key, done)));
}
