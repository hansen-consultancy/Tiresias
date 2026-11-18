using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class ServicePlannerTests
{
    static readonly VaultDocument Empty = new([], []);

    static ServicePlan Plan(ServiceInput input, VaultDocument? vault = null) => ServicePlanner.Plan(input, vault ?? Empty);

    static ServiceProblemKind[] Kinds(ServicePlan plan) => plan.Problems.Select(p => p.Kind).ToArray();

    [Test]
    public void Defaults_are_one_get_grant_named_default_using_the_service_slug_as_secret()
    {
        var plan = Plan(new("httpbin", "https://httpbin.org"));

        Assert.That(plan.Problems, Is.Empty);
        var grant = plan.Service!.Grants.Single();
        Assert.That(grant.Name, Is.EqualTo("default"));
        Assert.That(grant.SecretSlug, Is.EqualTo("httpbin"));
        Assert.That(grant.Rule.Methods, Is.EquivalentTo(new[] { "GET" }));
        Assert.That(grant.RequiresElevation, Is.False);
        Assert.That(plan.Service.Upstream, Is.EqualTo(new Uri("https://httpbin.org")));
    }

    [Test]
    public void No_allow_pattern_allows_every_path_and_says_so()
    {
        var plan = Plan(new("httpbin", "https://httpbin.org"));

        Assert.That(plan.AllowsEveryPath, Is.True);
        var rule = plan.Service!.Grants[0].Rule;
        Assert.That(rule.Covers(new("GET", "/anything/at/all?x=1", 0)), Is.True);
        Assert.That(rule.Covers(new("POST", "/anything", 0)), Is.False);
    }

    [Test]
    public void Allow_deny_methods_and_elevation_are_taken_as_given()
    {
        var plan = Plan(new("gh", "https://api.github.com", Secret: "gh-token", Methods: ["get", "POST,patch"],
            Allow: ["^/repos/", "^/user$"], Deny: ["^/repos/.*/hooks"], Grant: "write", RequiresElevation: true));

        Assert.That(plan.AllowsEveryPath, Is.False);
        var grant = plan.Service!.Grants.Single();
        Assert.That((grant.Name, grant.SecretSlug, grant.RequiresElevation), Is.EqualTo(("write", "gh-token", true)));
        Assert.That(grant.Rule.Methods, Is.EquivalentTo(new[] { "GET", "POST", "PATCH" }));
        Assert.That(grant.Rule.Covers(new("GET", "/user", 0)), Is.True);
        Assert.That(grant.Rule.Covers(new("GET", "/repos/a/b/hooks", 0)), Is.False);
        Assert.That(grant.Rule.Covers(new("GET", "/orgs", 0)), Is.False);
    }

    [Test]
    public void A_regex_with_a_comma_is_one_pattern()
    {
        var plan = Plan(new("api", "https://api.example.com", Allow: ["^/v[0-9]{1,2}/"]));

        Assert.That(plan.Service!.Grants[0].Rule.Allow.Single().ToString(), Is.EqualTo("^/v[0-9]{1,2}/"));
    }

    [Test]
    public void Needs_the_secret_only_when_the_vault_lacks_it()
    {
        using var vault = TestVault.Create();

        Assert.That(Plan(new("other", "https://api.example.com", Secret: "llm-read"), vault.Document).NeedsSecret, Is.False);
        Assert.That(Plan(new("other", "https://api.example.com"), vault.Document).NeedsSecret, Is.True);
    }

    [Test]
    public void An_existing_slug_is_refused_with_how_to_remove_it()
    {
        using var vault = TestVault.Create();
        var plan = Plan(new("llm", "https://api.example.com"), vault.Document);

        Assert.That(plan.Service, Is.Null);
        Assert.That(Kinds(plan), Is.EqualTo(new[] { ServiceProblemKind.SlugTaken }));
        Assert.That(plan.Problems[0].Message, Does.Contain("tir service remove llm"));
    }

    [TestCase("Upper")]
    [TestCase("-leading")]
    [TestCase("has space")]
    [TestCase("")]
    public void A_bad_slug_is_refused(string slug) =>
        Assert.That(Kinds(Plan(new(slug, "https://api.example.com"))), Does.Contain(ServiceProblemKind.SlugInvalid));

    [TestCase("http://api.example.com", ServiceProblemKind.UpstreamNotHttps)]
    [TestCase("httpbin.org", ServiceProblemKind.UpstreamInvalid)]
    [TestCase("ftp://api.example.com", ServiceProblemKind.UpstreamInvalid)]
    [TestCase("", ServiceProblemKind.UpstreamInvalid)]
    public void A_non_https_upstream_is_refused(string upstream, ServiceProblemKind kind) =>
        Assert.That(Kinds(Plan(new("api", upstream))), Is.EqualTo(new[] { kind }));

    [TestCase("http://localhost:5000")]
    [TestCase("http://127.0.0.1:8080/")]
    [TestCase("https://api.example.com/base/")]
    public void Https_or_loopback_http_is_accepted(string upstream) =>
        Assert.That(Plan(new("api", upstream)).Problems, Is.Empty);

    [Test]
    public void Plain_http_suggests_the_https_address()
    {
        var problem = Plan(new("api", "http://api.example.com/v1")).Problems.Single();

        Assert.That(problem.Detail, Is.EqualTo("https://api.example.com/v1"));
        Assert.That(problem.Message, Does.Contain("--upstream https://api.example.com/v1"));
    }

    [Test]
    public void A_missing_scheme_suggests_https()
    {
        var problem = Plan(new("api", "httpbin.org")).Problems.Single();

        Assert.That(problem.Message, Does.Contain("--upstream https://httpbin.org"));
    }

    [Test]
    public void An_invalid_regex_is_refused_with_its_field_and_reason()
    {
        var plan = Plan(new("api", "https://api.example.com", Allow: ["^/v1/("], Deny: ["[z-a]"]));

        Assert.That(plan.Service, Is.Null);
        Assert.That(plan.Problems.Select(p => (p.Field, p.Kind, p.Value)), Is.EqualTo(new[]
        {
            (ServiceField.Allow, ServiceProblemKind.AllowInvalid, "^/v1/("),
            (ServiceField.Deny, ServiceProblemKind.DenyInvalid, "[z-a]"),
        }));
        Assert.That(plan.Problems[0].Message, Does.Contain("--allow '^/v1/models$'"));
        Assert.That(plan.Problems.All(p => p.Detail is { Length: > 0 }), Is.True);
    }

    [Test]
    public void A_bad_method_secret_or_grant_name_is_refused()
    {
        var plan = Plan(new("api", "https://api.example.com", Secret: "Bad Secret", Methods: ["GET", "g3t"], Grant: "Read"));

        Assert.That(Kinds(plan), Is.EquivalentTo(new[]
            { ServiceProblemKind.SecretInvalid, ServiceProblemKind.GrantInvalid, ServiceProblemKind.MethodInvalid }));
    }

    [Test]
    public void Every_problem_is_reported_at_once()
    {
        var plan = Plan(new("Bad", "http://api.example.com", Allow: ["("]));

        Assert.That(Kinds(plan), Is.EqualTo(new[]
            { ServiceProblemKind.SlugInvalid, ServiceProblemKind.UpstreamNotHttps, ServiceProblemKind.AllowInvalid }));
    }

    [Test]
    public void The_planned_service_round_trips_through_the_vault_file()
    {
        var dir = Directory.CreateTempSubdirectory("tir-plan-").FullName;
        try
        {
            var service = Plan(new("httpbin", "https://httpbin.org", Allow: ["^/headers$"], Deny: ["secret"])).Service!;
            var path = Path.Combine(dir, "vault.json");
            VaultFile.Save(path, new([], [service]));

            var grant = VaultFile.Load(path).FindService("httpbin")!.Grants.Single();
            Assert.That(grant.Rule.Allow.Single().ToString(), Is.EqualTo("^/headers$"));
            Assert.That(grant.Rule.Deny!.Single().ToString(), Is.EqualTo("secret"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
