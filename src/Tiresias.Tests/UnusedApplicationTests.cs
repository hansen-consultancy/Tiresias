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
        Assert.That(FindingView.Button(check.Fix), Is.EqualTo((FixAction.OpenInstalledApps, "Finding_FixInstalledApps")));
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
        Assert.That(FindingView.Of([unused, warning], Dismissals.Empty).Open[^1].Single(), Is.EqualTo(unused));
    }
}
