using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class UnusedApplicationTests
{
    static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    const string Folder = @"C:\Users\alice\AppData\Local\Programs\Acme";
    const string Key = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme";

    static UninstallEntry Acme(string? folder = Folder, bool runsUnseen = false, bool uninstallerExists = true, string key = Key) =>
        new(key, "Acme", "2.1", $@"{Folder}\uninstall.exe", uninstallerExists, true, null, folder, runsUnseen);

    static ProgramRun Run(int daysAgo, string path = $@"{Folder}\acme.exe") => new(path, Now.AddDays(-daysAgo));

    static DoctorCheck[] Check(UninstallEntry entry, ProgramRun[] runs, params CredentialUse[] uses) =>
        [.. Doctor.UnusedApplications([entry], runs, uses, Now)];

    [Test]
    public void A_program_last_opened_over_90_days_ago_is_hygiene_with_Installed_apps()
    {
        var check = Check(Acme(), [Run(200), Run(120, $@"{Folder}\bin\helper.exe")]).Single();

        Assert.That(check.Name, Is.EqualTo("Acme 2.1 not opened since 2026-02-01"));
        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(check.Kind, Is.EqualTo(Doctor.UnusedAppKind));
        Assert.That(check.Fix, Is.EqualTo(new UninstallApp("Acme", Machine: false)));
        Assert.That(check.IsFinding, Is.True);
        Assert.That(FindingView.Button(check.Fix), Is.EqualTo((FixAction.OpenInstalledList, "Finding_FixInstalledList")));
    }

    [Test]
    public void Any_recent_run_under_its_folder_counts_as_use()
    {
        Assert.That(Check(Acme(), [Run(200), Run(10, $@"{Folder}\tools\acme-cli.exe")]), Is.Empty);
    }

    [Test]
    public void A_program_never_seen_running_is_unknown_not_unused()
    {
        Assert.That(Check(Acme(), [Run(5, @"C:\Users\alice\AppData\Local\Programs\Acme Other\other.exe")]), Is.Empty);
    }

    [Test]
    public void A_program_that_runs_unseen_is_never_unused()
    {
        Assert.That(Check(Acme(runsUnseen: true), [Run(200)]), Is.Empty);
    }

    [Test]
    public void A_program_that_used_a_credential_recently_is_not_unused()
    {
        Assert.That(Check(Acme(), [Run(200)], new CredentialUse($@"{Folder}\acme.exe", "github", Now.AddDays(-3))), Is.Empty);
    }

    [Test]
    public void A_shallow_or_unknown_folder_is_never_judged()
    {
        Assert.That(Check(Acme(folder: @"C:\Program Files"), [Run(200, @"C:\Program Files\acme.exe")]), Is.Empty);
        Assert.That(Check(Acme(folder: null), [Run(200)]), Is.Empty);
    }

    [Test]
    public void A_program_missing_its_uninstaller_is_left_to_the_repair_finding()
    {
        Assert.That(Check(Acme(uninstallerExists: false), [Run(200)]), Is.Empty);
    }

    [Test]
    public void A_machine_wide_program_says_it_needs_an_administrator()
    {
        var check = Check(Acme(key: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme"), [Run(200)]).Single();

        Assert.That(check.Fix!.Instruction, Is.EqualTo("uninstall Acme in Settings, Apps, Installed apps (needs an administrator)"));
    }

    [Test]
    public void Unused_programs_are_listed_but_never_badged()
    {
        var unused = Check(Acme(), [Run(200)]).Single();
        var warning = new DoctorCheck("acme starts at log-on unsigned", DoctorStatus.Warn, "detail", new RevealFile(@"C:\acme.exe"));

        Assert.That(FindingBadge.Open([unused, warning], Dismissals.Empty), Is.EquivalentTo(new[] { Dismissals.KeyOf(warning) }));
        Assert.That(FindingView.Of([unused, warning], Dismissals.Empty).Open.Last().Single(), Is.EqualTo(unused));
    }

    const string Programs = @"C:\Users\alice\AppData\Local\Programs\";

    static UninstallEntry Program(string name, bool runsUnseen = false, string? folder = null) =>
        new(Key + name, name, "1.0", null, false, true, null, folder ?? Programs + name, runsUnseen);

    [Test]
    public void The_installed_list_puts_unused_first_and_says_why_others_are_unknown()
    {
        ProgramRun[] runs = [Run(300, Programs + @"Old\old.exe"), Run(120, Programs + @"Older\b.exe"), Run(5, Programs + @"Busy\busy.exe"),
            Run(400, Programs + @"Tray\t.exe")];
        CredentialUse[] uses = [new(Programs + @"Agent\agent.exe", "github", Now.AddDays(-1))];

        var list = Doctor.InstalledPrograms(
            [Program("Busy"), Program("Tray", runsUnseen: true), Program("Older"), Program("Never"), Program("Old"), Program("Agent"),
             Program("Rooted", folder: @"C:\Program Files"), Program("old")], runs, uses, Now);

        Assert.That(list.Select(p => (p.Entry.Name, p.Use)), Is.EqualTo(new[]
        {
            ("Old", ProgramUse.Unused), ("Older", ProgramUse.Unused),
            ("Agent", ProgramUse.Recent), ("Busy", ProgramUse.Recent), ("Never", ProgramUse.NotRecorded),
            ("Rooted", ProgramUse.NotRecorded), ("Tray", ProgramUse.Background),
        }));
        Assert.That(list.Single(p => p.Entry.Name == "Agent").Reached, Is.EqualTo(new[] { "github" }));
        Assert.That(list[0].LastOpened, Is.EqualTo(Now.AddDays(-300)));
    }

    [Test]
    public void Unused_programs_on_Home_are_one_line_with_one_button_to_the_list()
    {
        var group = Doctor.UnusedApplications([Program("A"), Program("B")], [Run(200, Programs + @"A\a.exe"), Run(200, Programs + @"B\b.exe")], [], Now)
            .ToArray();
        var open = FindingView.Of(group, Dismissals.Empty).Open.Single();

        Assert.That(open, Has.Count.EqualTo(2));
        Assert.That(FindingView.Title(open), Is.EqualTo("2 programs you haven't opened in 90 days"));
        Assert.That(FindingView.GroupButton(open), Is.EqualTo((FixAction.OpenInstalledList, "Finding_FixInstalledList")));
    }

    [Test]
    public void A_group_of_findings_with_their_own_fixes_has_no_shared_button()
    {
        static DoctorCheck Unsigned(string path) => new($"{path} unsigned", DoctorStatus.Warn, "detail", new RevealFile(path), Kind: Doctor.UnsignedStartupKind);

        Assert.That(FindingView.GroupButton([Unsigned(@"C:\a.exe"), Unsigned(@"C:\b.exe")]), Is.Null);
    }
}
