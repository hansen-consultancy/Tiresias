using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class DismissalsTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);

    static DoctorCheck Sql(string server, string? database = "Orders") =>
        new("connection string Default in appsettings.json", DoctorStatus.Warn, "holds a password",
            new SetUpSqlServer(server, database), Position.Plaintext, new Position(Exposure.ShortLived, Control.Approved));

    [Test]
    public void A_dismissed_finding_is_found_again_by_the_same_line()
    {
        var dismissals = Dismissals.Empty.Dismiss(Sql("db.example.com"), "  only takes SQL logins ", Now);

        Assert.That(dismissals.For(Sql("db.example.com")), Is.EqualTo(new Dismissal(Dismissals.KeyOf(Sql("db.example.com")), Sql("db.example.com").Name, "only takes SQL logins", Now)));
    }

    [Test]
    public void A_finding_that_comes_back_changed_is_a_new_finding()
    {
        var dismissals = Dismissals.Empty.Dismiss(Sql("db.example.com"), "not mine", Now);

        Assert.That(dismissals.For(Sql("other.example.com")), Is.Null);
        Assert.That(dismissals.For(Sql("db.example.com", "Billing")), Is.Null);
        Assert.That(dismissals.For(Sql("db.example.com") with { Now = new Position(Exposure.Sealed, Control.Silent) }), Is.Null);
    }

    [Test]
    public void The_key_holds_no_server_or_path()
    {
        Assert.That(Dismissals.KeyOf(Sql("db.example.com")), Does.Match("^[0-9a-f]{64}$"));
    }

    [Test]
    public void Dismissing_again_replaces_the_reason()
    {
        var dismissals = Dismissals.Empty.Dismiss(Sql("db"), "first", Now).Dismiss(Sql("db"), "second", Now.AddDays(1));

        Assert.That(dismissals.Items.Select(d => d.Reason), Is.EqualTo(new[] { "second" }));
    }

    [TestCase("")]
    [TestCase("   ")]
    public void A_dismissal_needs_a_reason(string reason)
    {
        Assert.That(Dismissals.Empty.Dismiss(Sql("db"), reason, Now).Items, Is.Empty);
    }

    [Test]
    public void Only_a_finding_can_be_dismissed()
    {
        var health = new DoctorCheck("device key", DoctorStatus.Fail, "missing");

        Assert.That(Dismissals.Empty.Dismiss(health, "later", Now).Items, Is.Empty);
    }

    [Test]
    public void Restore_shows_the_finding_again()
    {
        var dismissals = Dismissals.Empty.Dismiss(Sql("db"), "not mine", Now);

        Assert.That(dismissals.Restore(Dismissals.KeyOf(Sql("db"))).For(Sql("db")), Is.Null);
    }

    [Test]
    public void Dismissals_round_trip_through_their_file()
    {
        var dismissals = Dismissals.Empty.Dismiss(Sql("db"), "not mine", Now);

        Assert.That(Dismissals.Parse(dismissals.ToJson()).Items, Is.EqualTo(dismissals.Items));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("{ not json")]
    [TestCase("""{"v":2,"items":[{"key":"k","name":"n","reason":"r","at":"2026-11-19T10:00:00Z"}]}""")]
    [TestCase("""{"v":1,"items":[{"key":"","name":"n","reason":"r","at":"2026-11-19T10:00:00Z"}]}""")]
    public void A_missing_damaged_or_newer_file_dismisses_nothing(string? json)
    {
        Assert.That(Dismissals.Parse(json).Items, Is.Empty);
    }
}

public class FindingViewTests
{
    static readonly DoctorCheck Health = new("device key", DoctorStatus.Ok, "present");
    static readonly DoctorCheck Variables = new("environment variables", DoctorStatus.Warn, "2 look like secrets",
        new ProtectVariables(["A", "B"]), Position.Plaintext, Position.SealedApproved);
    static readonly DoctorCheck Secrets = new("user secrets x", DoctorStatus.Fail, "plain", new ReviewUserSecrets("x"), Position.Plaintext, Position.SealedApproved);

    [Test]
    public void Findings_come_apart_from_the_other_checks_failures_first()
    {
        var split = FindingView.Of([Health, Variables, Secrets], Dismissals.Empty);

        Assert.That(split.Open, Is.EqualTo(new[] { Secrets, Variables }));
        Assert.That(split.Others, Is.EqualTo(new[] { Health }));
        Assert.That(split.Dismissed, Is.Empty);
    }

    [Test]
    public void A_dismissed_finding_is_listed_apart_with_its_reason()
    {
        var dismissals = Dismissals.Empty.Dismiss(Variables, "test machine", DateTimeOffset.UnixEpoch);

        var split = FindingView.Of([Health, Variables, Secrets], dismissals);

        Assert.That(split.Open, Is.EqualTo(new[] { Secrets }));
        Assert.That(split.Dismissed.Select(d => (d.Check, d.Dismissal.Reason)), Is.EqualTo(new[] { (Variables, "test machine") }));
    }

    [Test]
    public void Every_fix_the_doctor_offers_has_a_button()
    {
        DoctorFix[] fixes = [new ReviewUserSecrets("x"), new ProtectVariables(["A"]), new SetUpSqlServer("db", null), new SetUpRaven(@"C:\certs\a.pfx"), new ReferenceConfigurationPackage("Api.csproj")];

        Assert.That(fixes.Select(f => FindingView.Button(f)?.Action), Is.EqualTo(new FixAction?[]
        {
            FixAction.OpenSecrets, FixAction.OpenEnvironment, FixAction.SetUpSqlServer, FixAction.SetUpRaven, FixAction.CopyCommand,
        }));
        Assert.That(FindingView.Button(null), Is.Null);
    }

    [Test]
    public void Moves_reads_from_now_to_better()
    {
        Assert.That(FindingView.Moves(Variables), Is.EqualTo("E5/C3 → E4/C1"));
        Assert.That(FindingView.Moves(Variables with { Better = null }), Is.EqualTo("E5/C3"));
        Assert.That(FindingView.Moves(Health), Is.Empty);
    }
}
