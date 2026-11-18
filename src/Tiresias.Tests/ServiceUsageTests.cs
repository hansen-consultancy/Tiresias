using Tiresias.Policy;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class ServiceUsageTests
{
    static readonly VaultDocument Empty = new([], []);

    static Service Sql(string slug) =>
        SqlServerSetupPlanner.Plan(new(slug, "db.example.com", "Orders"), Empty).Service!;

    static Service Raven(string slug, bool changes = false) =>
        RavenSetupPlanner.Plan(new(slug, "https://a.raven.example.com", "Orders", changes), Empty).Service!;

    [Test]
    public void A_sql_service_reads_through_its_read_login_and_names_write_for_saving()
    {
        var usage = ServiceUsages.For(Sql("orders"));
        Assert.That(usage.Kind, Is.EqualTo(ServiceUsageKind.SqlLogin));
        Assert.That(usage.Snippet, Is.EqualTo("\"ConnectionStrings:Default\": \"tiresias:sql/orders/read\""));
        Assert.That(usage.Write, Is.EqualTo("write"));
    }

    [Test]
    public void The_snippet_is_a_reference_the_secrets_provider_understands()
    {
        var value = ServiceUsages.For(Sql("orders")).Snippet.Split('"')[3];
        Assert.That(SecretReferences.Parse(value), Is.EqualTo(new SecretReference(SecretReference.Sql, "orders", "read")));
    }

    [TestCase("Orders", "\"Database\": \"Orders\"")]
    [TestCase(null, "\"Database\": \"<database>\"")]
    [TestCase("  ", "\"Database\": \"<database>\"")]
    public void A_raven_service_names_the_database_when_it_is_known(string? database, string line)
    {
        var usage = ServiceUsages.For(Raven("orders-db", changes: true), database);
        Assert.That(usage.Kind, Is.EqualTo(ServiceUsageKind.Raven));
        Assert.That(usage.Snippet, Does.Contain("\"Urls\": [ \"tiresias:raven/orders-db\" ]").And.Contain(line));
        Assert.That(usage.Write, Is.Null);
    }

    [Test]
    public void Any_other_service_is_handed_out_as_a_placeholder_for_its_key()
    {
        var service = ServicePlanner.Plan(new("open-ai", "https://api.example.com/v1", "open-ai-key", ["POST"], []), Empty).Service!;
        var usage = ServiceUsages.For(service);
        Assert.That(usage.Kind, Is.EqualTo(ServiceUsageKind.Placeholder));
        Assert.That(usage.Snippet, Does.StartWith("tir env placeholder add OPEN_AI_API_KEY open-ai").And.Contain("OPEN_AI_BASE_URL"));
    }
}
