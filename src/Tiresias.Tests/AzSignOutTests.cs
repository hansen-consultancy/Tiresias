using System.Text.Json;
using NUnit.Framework;
using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class AzSignOutTests
{
    [TestCase(AzSignOut.Off, false)]
    [TestCase(AzSignOut.OnLock, true)]
    [TestCase(AzSignOut.Idle, false)]
    public void Only_the_lock_choice_signs_out_as_Tiresias_locks(AzSignOut setting, bool expected) =>
        Assert.That(AzSignOutPlan.OnLock(setting), Is.EqualTo(expected));

    [TestCase(AzSignOut.Off, 45, false)]
    [TestCase(AzSignOut.OnLock, 45, false)]
    [TestCase(AzSignOut.Idle, 29, false)]
    [TestCase(AzSignOut.Idle, 30, true)]
    [TestCase(AzSignOut.Idle, 45, true)]
    public void Only_the_idle_choice_signs_out_and_only_past_its_time(AzSignOut setting, int idleMinutes, bool expected) =>
        Assert.That(AzSignOutPlan.OnIdle(setting, 30, TimeSpan.FromMinutes(idleMinutes), done: false).SignOut, Is.EqualTo(expected));

    [Test]
    public void An_idle_stretch_signs_out_once_and_input_starts_the_next()
    {
        var first = AzSignOutPlan.OnIdle(AzSignOut.Idle, 15, TimeSpan.FromMinutes(15), done: false);
        var stillAway = AzSignOutPlan.OnIdle(AzSignOut.Idle, 15, TimeSpan.FromMinutes(16), first.Done);
        var back = AzSignOutPlan.OnIdle(AzSignOut.Idle, 15, TimeSpan.FromSeconds(20), stillAway.Done);
        var awayAgain = AzSignOutPlan.OnIdle(AzSignOut.Idle, 15, TimeSpan.FromMinutes(15), back.Done);

        Assert.That(new[] { first, stillAway, back, awayAgain }, Is.EqualTo(new[] { (true, true), (false, true), (false, false), (true, true) }));
    }

    [Test]
    public void Turning_the_setting_off_forgets_the_stretch() =>
        Assert.That(AzSignOutPlan.OnIdle(AzSignOut.Off, 15, TimeSpan.FromHours(2), done: true), Is.EqualTo((false, false)));

    [TestCase(15, 15)]
    [TestCase(0, 30)]
    [TestCase(-5, 30)]
    [TestCase(7, 30)]
    public void An_idle_time_About_does_not_offer_is_the_default(int saved, int expected) =>
        Assert.That(AzSignOutPlan.IdleMinutes(saved), Is.EqualTo(expected));

    [Test]
    public void The_setting_is_saved_by_name() =>
        Assert.That(JsonSerializer.Serialize(AzSignOut.OnLock), Is.EqualTo("\"OnLock\""));

    [Test, Platform("Win")]
    public void Az_is_the_first_on_PATH_quoted_folders_included()
    {
        const string Old = @"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd";
        const string New = @"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd";
        var path = @"C:\Windows\system32; ""C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin"" ;;C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin";

        Assert.That(AzSignOutPlan.Find(path, file => file is Old or New), Is.EqualTo(Old));
    }

    [Test, Platform("Win")]
    public void Az_missing_from_PATH_is_not_found() => Assert.Multiple(() =>
    {
        Assert.That(AzSignOutPlan.Find(@"C:\Windows\system32;C:\tools", _ => false), Is.Null);
        Assert.That(AzSignOutPlan.Find(null, _ => true), Is.Null);
        Assert.That(AzSignOutPlan.Find("", _ => true), Is.Null);
    });

    /// <summary>It runs through cmd: a folder relative to wherever the app runs, or one cmd would expand, is never taken.</summary>
    [TestCase(@"tools")]
    [TestCase(@".")]
    [TestCase(@"\tools")]
    [TestCase(@"C:\%TEMP%\tools")]
    [TestCase(@"C:\to""ols")]
    [Platform("Win")]
    public void A_folder_that_is_relative_or_that_cmd_would_rewrite_is_skipped(string folder) =>
        Assert.That(AzSignOutPlan.Find($@"{folder};C:\cli", _ => true), Is.EqualTo(@"C:\cli\az.cmd"));
}
