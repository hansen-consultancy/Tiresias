using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class UninstallEntryTests
{
    const string UserKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\";
    const string MachineKey = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\";
    const string Programs = @"C:\Users\alice\AppData\Local\Programs\";

    static UninstallEntry Entry(string name, string? version = "1.0", string? uninstaller = null, bool uninstallerExists = true, bool folderExists = true,
        string key = UserKey)
    {
        uninstaller ??= $@"{Programs}{name}\uninstall.exe";
        return new(key + name, name, version, uninstaller, uninstallerExists, folderExists, $"\"{uninstaller}\" --uninstall");
    }

    static DoctorCheck[] Run(params UninstallEntry[] entries) => [.. Doctor.UninstallEntries(entries)];

    [Test]
    public void An_entry_matching_the_disk_raises_nothing()
    {
        Assert.That(Run(Entry("Acme")), Is.Empty);
    }

    [Test]
    public void An_entry_whose_uninstaller_and_folder_are_gone_is_removed_as_an_entry()
    {
        var check = Run(Entry("Acme", uninstallerExists: false, folderExists: false)).Single();

        Assert.That(check.Name, Is.EqualTo("Acme 1.0 is listed but gone"));
        Assert.That(check.Kind, Is.EqualTo(Doctor.GoneEntryKind));
        Assert.That(check.Fix, Is.EqualTo(new RemoveEntry(UserKey + "Acme", "Acme")));
        Assert.That(check.Now, Is.Null);
        Assert.That(check.IsFinding, Is.True);
    }

    [Test]
    public void A_program_present_without_its_uninstaller_is_repaired_not_removed()
    {
        var check = Run(Entry("Acme", "2.3.1", uninstallerExists: false)).Single();

        Assert.That(check.Name, Is.EqualTo("Acme 2.3.1 can't be uninstalled"));
        Assert.That(check.Fix, Is.EqualTo(new Repair("Acme", "2.3.1")));
        Assert.That(check.Kind, Is.EqualTo(Doctor.NoUninstallerKind));
    }

    [Test]
    public void Repair_installs_the_same_version_with_winget_when_its_id_is_known()
    {
        Assert.That(new Repair("Acme", "2.3.1", "Acme.Tool").Instruction, Is.EqualTo("winget install --id Acme.Tool --exact --version 2.3.1 --force"));
        Assert.That(new Repair("Acme", "2.3.1").Instruction, Does.StartWith("reinstall Acme 2.3.1 over itself"));
    }

    [Test]
    public void An_older_versions_entry_naming_the_current_uninstaller_is_stale_and_warns_against_its_uninstall()
    {
        const string uninstaller = Programs + @"Acme\uninstall.exe";
        var check = Run(Entry("Acme", "1.9", uninstaller), Entry("Acme_2", "2.10", uninstaller)).Single();

        Assert.That(check.Name, Is.EqualTo("Acme 1.9 is a stale entry for Acme_2 2.10"));
        Assert.That(check.Detail, Does.Contain("Don't use Uninstall"));
        Assert.That(check.Fix, Is.EqualTo(new RemoveEntry(UserKey + "Acme", "Acme")));
        Assert.That(check.Kind, Is.EqualTo(Doctor.StaleEntryKind));
    }

    [Test]
    public void Products_sharing_an_uninstaller_with_their_own_arguments_are_not_duplicates()
    {
        const string engine = @"C:\Program Files (x86)\Acme\Installer\setup.exe";
        Assert.That(Run(Entry("Acme Studio", "18.0", engine) with { Command = $"\"{engine}\" uninstall --product studio" },
            Entry("Acme Manager", "22.0", engine) with { Command = $"\"{engine}\" uninstall --product manager" }), Is.Empty);
    }

    [Test]
    public void A_name_that_already_holds_its_version_isnt_repeated()
    {
        Assert.That(Run(Entry("Acme 2.1", "2.1", uninstallerExists: false, folderExists: false)).Single().Name, Is.EqualTo("Acme 2.1 is listed but gone"));
    }

    [TestCase("1.0", "1.0")]
    [TestCase("1.0", null)]
    [TestCase("beta", "1.0")]
    public void Entries_sharing_an_uninstaller_whose_versions_cant_be_ordered_raise_nothing(string? a, string? b)
    {
        const string uninstaller = Programs + @"Acme\uninstall.exe";
        Assert.That(Run(Entry("A", a, uninstaller), Entry("B", b, uninstaller)), Is.Empty);
    }

    [Test]
    public void An_entry_that_names_no_uninstaller_on_disk_says_nothing()
    {
        Assert.That(Run(new UninstallEntry(UserKey + "Acme", "Acme", "1.0", null, false, false)), Is.Empty);
    }

    [Test]
    public void A_machine_wide_entry_needs_an_administrator_and_gets_the_commands_in_the_app()
    {
        var check = Run(Entry("Acme", uninstallerExists: false, folderExists: false, key: MachineKey)).Single();
        var fix = (RemoveEntry)check.Fix!;

        Assert.That(check.Detail, Does.Contain("administrator"));
        Assert.That(fix.Instruction, Does.EndWith("as an administrator"));
        Assert.That(FindingView.Button(fix)?.Action, Is.EqualTo(FixAction.CopyCommand));
        Assert.That(FindingView.Button(new RemoveEntry(UserKey + "Acme", "Acme"))?.Action, Is.EqualTo(FixAction.RemoveEntry));
    }

    [Test]
    public void Repair_gets_a_button_only_with_a_command_to_copy()
    {
        Assert.That(FindingView.Button(new Repair("Acme", "1.0", "Acme.Tool"))?.Action, Is.EqualTo(FixAction.CopyCommand));
        Assert.That(FindingView.Button(new Repair("Acme", "1.0")), Is.Null);
    }

    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme", true)]
    [TestCase(@"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{0A1B-2C3D}", true)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall", false)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme\Sub", false)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Acme", false)]
    [TestCase("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Acme\" /f", false)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme & start calc", false)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme$(calc)", false)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme %PATH%", false)]
    [TestCase(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Opera GX 139.0.6053.63", true)]
    public void Only_an_uninstall_subkey_can_be_removed(string key, bool safe) =>
        Assert.That(RemoveEntry.IsSafeKey(key), Is.EqualTo(safe));

    [Test]
    public void An_entry_whose_key_isnt_plain_is_reported_without_a_command()
    {
        var check = Run(Entry("Acme\" & start calc & rem", uninstallerExists: false, folderExists: false)).Single();

        Assert.That(check.Fix, Is.Null);
        Assert.That(check.IsFinding, Is.False);
    }

    [TestCase("Acme.Tool", "1.0 & calc")]
    [TestCase("Acme.Tool;calc", "1.0")]
    public void Repair_builds_no_winget_command_from_values_that_arent_plain(string id, string version)
    {
        var repair = new Repair("Acme", version, id);

        Assert.That(repair.Command, Is.Null);
        Assert.That(repair.Instruction, Does.StartWith("reinstall Acme"));
        Assert.That(FindingView.Button(repair), Is.Null);
    }

    [Test]
    public void The_backup_is_named_after_the_key_without_what_a_file_name_cant_hold()
    {
        Assert.That(new RemoveEntry(UserKey + "Acme: Tool*", "Acme").BackupName, Is.EqualTo("Acme_ Tool_.reg"));
    }

    [Test]
    public void A_dismissed_entry_finding_stays_dismissed_on_the_next_run()
    {
        var check = Run(Entry("Acme", uninstallerExists: false, folderExists: false)).Single();
        var dismissals = Dismissals.Empty.Dismiss(check, "leftover I keep", DateTimeOffset.UnixEpoch);

        Assert.That(dismissals.For(Run(Entry("Acme", uninstallerExists: false, folderExists: false)).Single()), Is.Not.Null);
    }
}
