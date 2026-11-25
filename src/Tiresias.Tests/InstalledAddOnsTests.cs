using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class InstalledAddOnsTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);
    static readonly ExtensionHost Code = new("VS Code", "Code.exe", "code");
    static readonly ExtensionHost Cursor = new("Cursor", "Cursor.exe", "cursor");

    [Test]
    public void Extensions_carry_their_hosts_reach_and_the_most_reaching_come_first()
    {
        var list = InstalledAddOns.Extensions(
            [new(Cursor, "zed.tool", "1.0", "Zed", null), new(Code, "beta.tool", "2.0", null, Now.AddDays(-3)), new(Code, "acme.helper", "1.0", "Acme", null)],
            [new(@"C:\Programs\VS Code\Code.exe", "openai", Now.AddDays(-1)), new(@"C:\Programs\VS Code\Code.exe", "github", Now.AddDays(-2)),
             new(@"C:\Programs\VS Code\Code.exe", "github", Now.AddDays(-5)), new(@"C:\Programs\Cursor\Cursor.exe", "github", Now.AddDays(-200))],
            Now);

        Assert.That(list.Select(a => (a.Name, a.In, string.Join(",", a.Reached))), Is.EqualTo(new[]
        {
            ("acme.helper", "VS Code", "github,openai"),
            ("beta.tool", "VS Code", "github,openai"),
            ("zed.tool", "Cursor", ""),
        }));
        Assert.That(list[1].Updated, Is.EqualTo(Now.AddDays(-3)));
    }

    [Test]
    public void Tools_come_from_the_days_listing_by_manager_then_id()
    {
        var list = InstalledAddOns.Tools(new(Now, [new("npm", "sass", "1.0"), new("dotnet", "zeta", "2.0"), new("dotnet", "Acme.Cli", null)]));

        Assert.That(list.Select(a => $"{a.In} {a.Name}"), Is.EqualTo(new[] { "dotnet Acme.Cli", "dotnet zeta", "npm sass" }));
        Assert.That(list.All(a => a.Publisher is null && a.Reached.Count == 0), Is.True);
    }

    [TestCase("", 2)]
    [TestCase("github", 1)]
    [TestCase("ACME code", 1)]
    [TestCase("acme cursor", 0)]
    [TestCase("2.0", 1)]
    public void Search_matches_every_word_anywhere(string search, int count)
    {
        AddOn[] list = [new("acme.helper", "1.0", "VS Code", "Acme", null, ["github"]), new("beta", "2.0", "Cursor", null, null, [])];

        Assert.That(InstalledAddOns.Filter(list, search).Count(), Is.EqualTo(count));
    }
}
