using System.Text;
using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class RavenClearanceTests
{
    static readonly DoctorRavenCertificate Orders = new("orders", "orders-app", "ABCDEF0123456789", DateTimeOffset.UtcNow.AddYears(1));

    static DoctorCheck Check(DoctorRavenClearance? clearance, DoctorRavenCertificate? certificate = null) =>
        Doctor.RavenClearance([(certificate ?? Orders, clearance)]).Single();

    static DoctorRavenClearance Clearance(string level, params string[] databases) =>
        new(level, databases.ToDictionary(d => d, _ => "ReadWrite"));

    [TestCase("ClusterAdmin")]
    [TestCase("Operator")]
    public void A_certificate_that_can_change_the_server_warns_with_its_replacement(string level)
    {
        var check = Check(Clearance(level));

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Name, Is.EqualTo("RavenDB clearance of orders-app for orders (ABCDEF01)"));
        Assert.That(check.Detail, Does.StartWith($"{level}: a program using orders can change the server"));
        Assert.That(check.Fix, Is.EqualTo(new ReplaceRavenCertificate("orders")));
        Assert.That((check.Now, check.Better), Is.EqualTo(((Position?)null, (Position?)null)));
        Assert.That(check.IsFinding);
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.ReplaceRaven));
    }

    [Test]
    public void A_valid_user_for_three_databases_warns_naming_them()
    {
        var check = Check(Clearance("ValidUser", "orders", "billing", "audit"));

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Detail, Does.StartWith("ValidUser for 3 databases: audit (ReadWrite), billing (ReadWrite), orders (ReadWrite)."));
        Assert.That(check.Fix, Is.EqualTo(new ReplaceRavenCertificate("orders")));
    }

    [Test]
    public void A_valid_user_for_one_database_is_ok()
    {
        var check = Check(new("ValidUser", new Dictionary<string, string> { ["orders"] = "Read" }));

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(check.Detail, Is.EqualTo("ValidUser, limited to orders (Read)"));
        Assert.That(check.IsFinding, Is.False);
    }

    [Test]
    public void Admin_on_its_one_database_warns()
    {
        var check = Check(new("ValidUser", new Dictionary<string, string> { ["orders"] = "Admin" }));

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Detail, Does.StartWith("ValidUser, Admin on orders (Admin): a program using orders can change the database's indexes and settings"));
        Assert.That(check.Fix, Is.EqualTo(new ReplaceRavenCertificate("orders")));
    }

    [Test]
    public void An_unanswered_question_is_skipped_not_a_finding()
    {
        var check = Check(null);

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(check.Detail, Does.StartWith("skipped"));
        Assert.That(check.IsFinding, Is.False);
    }

    [Test]
    public void A_new_certificate_is_a_new_finding()
    {
        var old = Check(Clearance("Operator"));
        var replaced = Check(Clearance("Operator"), Orders with { Thumbprint = "0011223344556677" });

        Assert.That(Dismissals.KeyOf(replaced), Is.Not.EqualTo(Dismissals.KeyOf(old)));
    }

    [Test]
    public void It_never_shares_a_dismissal_with_the_expiry_finding()
    {
        var expiring = Doctor.RavenExpiry([Orders with { NotAfter = DateTimeOffset.UtcNow.AddDays(3) }], DateTimeOffset.UtcNow).Single();
        Assert.That(Dismissals.KeyOf(Check(Clearance("Operator"))), Is.Not.EqualTo(Dismissals.KeyOf(expiring)));
    }

    [Test]
    public void A_certificate_recorded_before_metadata_is_named_by_its_service() =>
        Assert.That(Check(Clearance("Operator"), new("orders", null, null, null)).Name, Is.EqualTo("RavenDB clearance for orders"));

    [Test]
    public void The_broker_answer_reads_into_a_clearance()
    {
        var clearance = DoctorRavenClearance.FromBroker(Encoding.UTF8.GetBytes("""{"clearance":"ValidUser","databases":{"orders":"ReadWrite"}}"""));

        Assert.That(clearance!.Level, Is.EqualTo("ValidUser"));
        Assert.That(clearance.Databases, Is.EqualTo(new Dictionary<string, string> { ["orders"] = "ReadWrite" }));
    }

    [TestCase("")]
    [TestCase("[]")]
    [TestCase("""{"databases":{}}""")]
    [TestCase("""{"clearance":3}""")]
    [TestCase("not json")]
    public void Anything_else_reads_as_unanswered(string body) =>
        Assert.That(DoctorRavenClearance.FromBroker(Encoding.UTF8.GetBytes(body)), Is.Null);
}
