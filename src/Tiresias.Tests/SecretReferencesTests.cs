using System.Text.Json.Nodes;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.Tests;

public class SecretReferencesTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 18, 9, 0, 0, TimeSpan.Zero);

    [Test]
    public void A_sql_reference_names_its_service_and_grant() =>
        Assert.That(SecretReferences.Parse("tiresias:sql/appdb/read"), Is.EqualTo(new SecretReference("sql", "appdb", "read")));

    [TestCase("Server=db;Password=x")]
    [TestCase("Tiresias:sql/appdb/read")]
    public void An_ordinary_value_is_not_a_reference(string value) =>
        Assert.That(SecretReferences.Parse(value), Is.Null);

    [TestCase("tiresias:sql/appdb")]
    [TestCase("tiresias:sql//read")]
    [TestCase("tiresias:raven/appdb/read")]
    [TestCase("tiresias:sql/appdb/read/extra")]
    public void A_malformed_reference_says_what_it_should_look_like(string value) =>
        Assert.That(() => SecretReferences.Parse(value), Throws.TypeOf<InvalidDataException>().With.Message.Contains("tiresias:sql/<service>/<grant>"));

    [Test]
    public void References_are_found_anywhere_with_their_configuration_key()
    {
        var doc = JsonNode.Parse("""{ "ConnectionStrings": { "Db": "tiresias:sql/appdb/write" }, "Replicas": [ "x", "tiresias:sql/appdb/read" ], "N": 3 }""")!;
        Assert.That(SecretReferences.Find(doc).Select(f => f.Key), Is.EqualTo(new[] { "ConnectionStrings:Db", "Replicas:1" }));
    }

    [Test]
    public async Task Resolving_replaces_each_reference_in_place_and_renews_at_80_percent_of_the_earliest_expiry()
    {
        var doc = JsonNode.Parse("""{ "A": "tiresias:sql/appdb/read", "B": "tiresias:sql/other/write", "C": "plain" }""")!;
        var expiries = new Dictionary<string, DateTimeOffset?> { ["appdb"] = Now.AddHours(10), ["other"] = Now.AddHours(5) };

        var renewAt = await SecretReferences.ResolveAsync(doc, Now, (_, r) => Task.FromResult(new ResolvedSecret($"login-{r.Service}", expiries[r.Service])));

        Assert.That(doc.ToJsonString(), Is.EqualTo("""{"A":"login-appdb","B":"login-other","C":"plain"}"""));
        Assert.That(renewAt, Is.EqualTo(Now.AddHours(4)));
    }

    [Test]
    public async Task Nothing_that_expires_means_no_renewal()
    {
        var doc = JsonNode.Parse("""{ "A": "plain" }""")!;
        Assert.That(await SecretReferences.ResolveAsync(doc, Now, (_, _) => throw new AssertionException("no reference")), Is.Null);
    }

    [Test]
    public void An_expiry_already_past_renews_now() =>
        Assert.That(SecretReferences.RenewAt(Now, Now.AddMinutes(-1)), Is.EqualTo(Now));

    [TestCase("""{ "Db": "tiresias:sql/appdb/read" }""", true)]
    [TestCase("""{ "Db": "Server=x", /* tiresias:sql/appdb/read */ }""", false)]
    [TestCase("""{ "tiresias:sql/appdb/read": "x" }""", false)]
    [TestCase("""{ "Db": "Server=x" }""", false)]
    public void A_plain_file_names_references_only_in_string_values(string json, bool names) =>
        Assert.That(SecretsFile.NamesReferences(json), Is.EqualTo(names));
}
