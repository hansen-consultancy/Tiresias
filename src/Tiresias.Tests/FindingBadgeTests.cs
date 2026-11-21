using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class FindingBadgeTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);
    static readonly DoctorCheck Health = new("device key", DoctorStatus.Ok, "present");

    static DoctorCheck Sql(string server) =>
        new($"connection string for {server}", DoctorStatus.Warn, "password", new SetUpSqlServer(server, "Orders"), Position.Plaintext);

    [Test]
    public void Every_open_finding_is_new_until_Home_shows_it()
    {
        DoctorCheck[] checks = [Health, Sql("db1"), Sql("db2")];
        var open = FindingBadge.Open(checks, Dismissals.Empty);

        Assert.That(FindingBadge.New(open, FindingBadge.Parse(null)), Is.EqualTo(2));
        Assert.That(FindingBadge.New(open, open), Is.Zero);
    }

    [Test]
    public void A_finding_that_comes_back_changed_is_new_again()
    {
        var seen = FindingBadge.Open([Sql("db1")], Dismissals.Empty);

        Assert.That(FindingBadge.New(FindingBadge.Open([Sql("db1"), Sql("db3")], Dismissals.Empty), seen), Is.EqualTo(1));
    }

    [Test]
    public void A_dismissed_finding_never_counts()
    {
        var dismissals = Dismissals.Empty.Dismiss(Sql("db1"), "only takes SQL logins", Now);

        Assert.That(FindingBadge.New(FindingBadge.Open([Sql("db1")], dismissals), FindingBadge.Parse(null)), Is.Zero);
    }

    [Test]
    public void A_finding_gone_and_back_is_new_again_once_Home_showed_it_gone()
    {
        var seenWithout = FindingBadge.Open([Health], Dismissals.Empty);

        Assert.That(FindingBadge.New(FindingBadge.Open([Sql("db1")], Dismissals.Empty), seenWithout), Is.EqualTo(1));
    }

    [Test]
    public void Seen_keys_round_trip_and_hold_no_names()
    {
        var open = FindingBadge.Open([Sql("db1.example.com")], Dismissals.Empty);
        var json = FindingBadge.ToJson(open);

        Assert.That(json, Does.Not.Contain("db1"));
        Assert.That(FindingBadge.Parse(json), Is.EquivalentTo(open));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("not json")]
    [TestCase("{\"v\":2,\"keys\":[\"a\"]}")]
    [TestCase("{\"v\":1}")]
    public void A_missing_damaged_or_newer_file_counts_everything_as_new(string? json) =>
        Assert.That(FindingBadge.Parse(json), Is.Empty);
}
