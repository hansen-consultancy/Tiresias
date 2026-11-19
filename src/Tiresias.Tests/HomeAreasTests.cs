using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class HomeAreasTests
{
    static readonly HomeFacts Empty = new(0, false, false, false, false, [], []);

    [Test]
    public void A_machine_with_nothing_in_use_shows_no_area() =>
        Assert.That(HomeAreas.Plan(Empty), Is.Empty);

    [Test]
    public void Each_area_appears_with_content() => Assert.Multiple(() =>
    {
        Assert.That(HomeAreas.Plan(Empty with { Services = 1 }), Is.EquivalentTo(new[] { HomeArea.Services }));
        Assert.That(HomeAreas.Plan(Empty with { SealedUserSecrets = true }), Is.EquivalentTo(new[] { HomeArea.UserSecrets }));
        Assert.That(HomeAreas.Plan(Empty with { ProjectFolders = true }), Is.EquivalentTo(new[] { HomeArea.UserSecrets }));
        Assert.That(HomeAreas.Plan(Empty with { SealedVariables = true }), Is.EquivalentTo(new[] { HomeArea.EnvironmentVariables }));
        Assert.That(HomeAreas.Plan(Empty with { ActivityRecorded = true }), Is.EquivalentTo(new[] { HomeArea.Activity }));
    });

    [Test]
    public void A_fact_that_cannot_be_read_shows_its_area() =>
        Assert.That(HomeAreas.Plan(new(null, null, false, null, null, [], [])), Is.EquivalentTo(Enum.GetValues<HomeArea>()));

    [Test]
    public void An_unreadable_project_index_shows_user_secrets() =>
        Assert.That(HomeAreas.Plan(Empty with { ProjectFolders = null }), Is.EquivalentTo(new[] { HomeArea.UserSecrets }));

    [Test]
    public void A_finding_keeps_the_area_its_fix_opens() => Assert.Multiple(() =>
    {
        Assert.That(HomeAreas.Plan(Empty with { Fixes = [new SetUpSqlServer("db.example.com", null)] }), Is.EquivalentTo(new[] { HomeArea.Services }));
        Assert.That(HomeAreas.Plan(Empty with { Fixes = [new SetUpRaven("cert.pfx")] }), Is.EquivalentTo(new[] { HomeArea.Services }));
        Assert.That(HomeAreas.Plan(Empty with { Fixes = [new ProtectVariables(["OPENAI_API_KEY"])] }), Is.EquivalentTo(new[] { HomeArea.EnvironmentVariables }));
        Assert.That(HomeAreas.Plan(Empty with { Fixes = [new ReviewUserSecrets("id")] }), Is.EquivalentTo(new[] { HomeArea.UserSecrets }));
        Assert.That(HomeAreas.Plan(Empty with { Fixes = [new ReferenceConfigurationPackage("app.csproj")] }), Is.Empty);
    });

    [Test]
    public void An_area_opened_this_session_stays() =>
        Assert.That(HomeAreas.Plan(Empty with { Opened = [HomeArea.Services] }), Is.EquivalentTo(new[] { HomeArea.Services }));

    [Test]
    public void Every_option_of_what_do_you_need_leads_to_an_area_or_a_guide() => Assert.Multiple(() =>
    {
        foreach (var option in NeedCatalog.Needs.SelectMany(n => n.Options))
        {
            var step = NeedView.Button(option.Action).Step;
            Assert.That(step == NeedStep.OpenGuide || HomeAreas.Of(step) is not null, option.Id);
            Assert.That(HomeAreas.Of(step), Is.EqualTo(HomeAreas.Of(option.Action)), option.Id);
        }
    });
}
