using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Decoys;

namespace Tiresias.Tests;

public class DeveloperToolsTests
{
    static Dictionary<DeveloperSignal, bool?> None() => Enum.GetValues<DeveloperSignal>().ToDictionary(s => s, s => (bool?)false);

    [Test]
    public void Auto_without_a_signal_hides_the_tools() =>
        Assert.That(DeveloperTools.Plan(None(), DeveloperToolsSetting.Auto), Is.EqualTo(new DeveloperView(false, [])).Using<DeveloperView>(Same));

    [Test]
    public void Auto_shows_them_with_the_signals_found_an_unreadable_one_counting_as_found()
    {
        var signals = None();
        signals[DeveloperSignal.Git] = true;
        signals[DeveloperSignal.DotNetSdk] = null;

        var view = DeveloperTools.Plan(signals, DeveloperToolsSetting.Auto);

        Assert.That(view.Shown, Is.True);
        Assert.That(view.Because, Is.EqualTo(new[] { DeveloperSignal.DotNetSdk, DeveloperSignal.Git }));
    }

    [Test]
    public void On_and_off_override_the_signals_and_name_none() => Assert.Multiple(() =>
    {
        var signals = None();
        signals[DeveloperSignal.Git] = true;
        Assert.That(DeveloperTools.Plan(None(), DeveloperToolsSetting.On), Is.EqualTo(new DeveloperView(true, [])).Using<DeveloperView>(Same));
        Assert.That(DeveloperTools.Plan(signals, DeveloperToolsSetting.Off), Is.EqualTo(new DeveloperView(false, [])).Using<DeveloperView>(Same));
    });

    [Test]
    public void Every_signal_has_its_words() => Assert.Multiple(() =>
    {
        foreach (var signal in Enum.GetValues<DeveloperSignal>())
            Assert.That(DeveloperTools.Key(signal), Is.EqualTo($"DevSignal_{signal}"));
    });

    [Test]
    public void Home_says_why_only_when_auto_decided_and_until_closed() => Assert.Multiple(() =>
    {
        var auto = new DeveloperView(true, [DeveloperSignal.Git]);
        Assert.That(DeveloperTools.ShowHomeLine(auto, noted: false), Is.True);
        Assert.That(DeveloperTools.ShowHomeLine(auto, noted: true), Is.False);
        Assert.That(DeveloperTools.ShowHomeLine(new(true, []), noted: false), Is.False);
    });

    [Test]
    public void Developer_tools_add_their_areas_to_home() =>
        Assert.That(HomeAreas.Plan(new(0, false, false, false, false, [], [], DeveloperTools: true)),
            Is.EquivalentTo(new[] { HomeArea.UserSecrets, HomeArea.Services, HomeArea.EnvironmentVariables }));

    [Test]
    public void Without_them_a_developer_check_that_passed_is_left_out_and_nothing_else()
    {
        DoctorCheck[] checks =
        [
            new("broker pinned", DoctorStatus.Ok, "enrolled"),
            new("git credentials", DoctorStatus.Ok, "none in plain text") { ForDevelopers = true },
            new("config", DoctorStatus.Warn, "a key in plain text") { ForDevelopers = true },
        ];

        var others = FindingView.Of(checks, Dismissals.Empty, developerTools: false).Others;

        Assert.That(others.Select(c => c.Name), Is.EqualTo(new[] { "broker pinned", "config" }));
    }

    [Test]
    public void Without_them_a_solo_note_shows_as_passed()
    {
        DoctorCheck[] checks = [new("egress", DoctorStatus.Warn, "no fixed IP") { SoloNote = true }];

        Assert.Multiple(() =>
        {
            Assert.That(FindingView.Of(checks, Dismissals.Empty, developerTools: false).Others.Single().Status, Is.EqualTo(DoctorStatus.Ok));
            Assert.That(FindingView.Of(checks, Dismissals.Empty).Others.Single().Status, Is.EqualTo(DoctorStatus.Warn));
        });
    }

    [Test]
    public void Developer_needs_are_listed_with_the_tools_or_when_searched_for()
    {
        var all = NeedMatcher.Match(null);

        Assert.Multiple(() =>
        {
            Assert.That(NeedView.Listed(all, "", developerTools: false).Any(m => m.Need.ForDevelopers), Is.False);
            Assert.That(NeedView.Listed(all, "", developerTools: false), Is.Not.Empty);
            Assert.That(NeedView.Listed(all, "", developerTools: true), Has.Count.EqualTo(all.Count));
            Assert.That(NeedView.Listed(all, "nuget", developerTools: false), Has.Count.EqualTo(all.Count));
        });
    }

    [Test]
    public void Every_developer_need_exists() =>
        Assert.That(NeedCatalog.Needs.Count(n => n.ForDevelopers), Is.EqualTo(6));

    [Test]
    public void Without_them_no_project_decoy_is_offered() =>
        Assert.That(DecoyCard.Of(null, developerTools: false).Placeable, Is.EqualTo(new[] { DecoyKind.PasswordsFile, DecoyKind.Variables }));

    [Test]
    public void Without_them_the_tray_does_not_name_solo_mode() => Assert.Multiple(() =>
    {
        var solo = new AgentSnapshot(SetUp: true, Unlocked: true, Enrolled: true, Solo: true);
        Assert.That(TrayStatus.Describe(solo, developerTools: false).Mode, Is.Null);
        Assert.That(TrayStatus.Describe(solo).Mode, Is.Not.Null);
    });

    static bool Same(DeveloperView a, DeveloperView b) => a.Shown == b.Shown && a.Because.SequenceEqual(b.Because);
}
