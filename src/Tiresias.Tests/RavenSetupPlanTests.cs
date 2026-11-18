using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class RavenSetupPlanTests
{
    static readonly VaultDocument Empty = new([], []);

    static RavenSetupPlan Plan(string slug = "orders", string server = "https://a.raven.example.com", string database = "Orders",
        bool changes = false, VaultDocument? vault = null) =>
        RavenSetupPlanner.Plan(new(slug, server, database, changes), vault ?? Empty);

    [Test]
    public void A_server_becomes_a_service_with_one_grant_that_presents_the_certificate_on_any_path()
    {
        var plan = Plan();
        var service = plan.Service!;
        Assert.That(service.Upstream, Is.EqualTo(new Uri("https://a.raven.example.com/")));
        var grant = service.Grants.Single();
        Assert.That((grant.Name, grant.SecretSlug, grant.IssuesLogins), Is.EqualTo(("app", "orders-certificate", false)));
        Assert.That(grant.Rule.Covers(new("PUT", "/databases/Orders/docs?id=orders/1", 10)), Is.True);
        Assert.That(grant.Rule.Covers(new("WEBSOCKET", "/databases/Orders/changes", 0)), Is.False);
        Assert.That((plan.CertificateSecret, plan.Database, plan.Replaces), Is.EqualTo(("orders-certificate", "Orders", false)));
    }

    [Test]
    public void Allowing_changes_adds_websocket_to_the_grant() =>
        Assert.That(Plan(changes: true).Service!.Grants.Single().Rule.Covers(new("WEBSOCKET", "/databases/Orders/changes", 0)), Is.True);

    [TestCase("https://a.raven.example.com/", "https://a.raven.example.com/")]
    [TestCase(" https://A.raven.example.com:8443 ", "https://a.raven.example.com:8443/")]
    public void The_upstream_is_the_server_root_however_it_was_typed(string server, string upstream) =>
        Assert.That(Plan(server: server).Service!.Upstream, Is.EqualTo(new Uri(upstream)));

    [TestCase("", "Type the server's address")]
    [TestCase("http://a.raven.example.com", "unsecured")]
    [TestCase("https://a.raven.example.com/studio", "isn't a server address")]
    [TestCase("https://a.raven.example.com/?x=1", "isn't a server address")]
    [TestCase("https://me@a.raven.example.com", "isn't a server address")]
    [TestCase("a.raven.example.com", "isn't a server address")]
    public void A_server_that_isnt_an_https_root_is_refused_with_why(string server, string message) =>
        Assert.That(Plan(server: server).Problems.Single(), Has.Property("Field").EqualTo(RavenSetupField.Server).And.Property("Message").Contains(message));

    [TestCase("")]
    [TestCase("Ord/ers")]
    [TestCase("Ord?ers")]
    public void A_database_that_cant_be_one_is_refused(string database) =>
        Assert.That(Plan(database: database).Problems.Single().Field, Is.EqualTo(RavenSetupField.Database));

    [TestCase("Orders")]
    [TestCase("")]
    public void A_slug_that_isnt_one_is_refused(string slug) =>
        Assert.That(Plan(slug: slug).Problems.Single().Field, Is.EqualTo(RavenSetupField.Slug));

    [Test]
    public void The_same_service_for_the_same_server_is_set_up_again_and_another_is_refused()
    {
        var vault = Empty with { Services = [Plan().Service!] };
        Assert.That(Plan(server: "https://A.raven.example.com/", vault: vault).Replaces, Is.True);

        var other = Plan(server: "https://b.raven.example.com", vault: vault);
        Assert.That(other.Service, Is.Null);
        Assert.That(other.Problems.Single().Message, Does.Contain("exists already for https://a.raven.example.com/"));
    }
}
