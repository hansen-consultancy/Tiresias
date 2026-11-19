using System.Text.RegularExpressions;
using Tiresias.Policy;

namespace Tiresias.Tests;

public class GrantSelectorTests
{
    static RequestRule Rule(string methods, params string[] allow) =>
        new(methods.Split(',').ToHashSet(), allow.Select(a => new Regex(a)).ToArray());

    // The llm.example.com shape: one service, three keys.
    static readonly Service Llm = new("llm", new Uri("https://llm.example.com"),
    [
        new Grant("read", "llm-read", Rule("GET", "^/v1/(models|status)")),
        new Grant("write", "llm-write", Rule("GET,POST", "^/v1/")),
        new Grant("admin", "llm-admin", Rule("GET,POST,DELETE", "^/"), RequiresElevation: true),
    ]);

    static readonly IReadOnlySet<string> None = new HashSet<string>();

    static GrantDecision Select(string method, string path, string? ceiling = null, IReadOnlySet<string>? elevated = null) =>
        GrantSelector.Select(Llm, new BrokeredRequest(method, path, 0), ceiling, elevated ?? None);

    [Test]
    public void Picks_the_least_privileged_grant_that_covers_the_request()
    {
        Assert.That(Select("GET", "/v1/models").Grant?.Name, Is.EqualTo("read"));
        Assert.That(Select("POST", "/v1/chat/completions").Grant?.Name, Is.EqualTo("write"));
    }

    [Test]
    public void A_read_ceiling_never_reaches_write_even_when_write_would_cover_it()
    {
        var decision = Select("POST", "/v1/chat/completions", ceiling: "read");
        Assert.That(decision.Allowed, Is.False);
        Assert.That(decision.Reason, Is.EqualTo(DenyReason.NotCovered));
    }

    [Test]
    public void Removing_a_named_ceiling_invalidates_the_old_approval()
    {
        var updated = Llm with { Grants = Llm.Grants.Where(grant => grant.Name != "read").ToArray() };
        var decision = GrantSelector.Select(updated, new("POST", "/v1/jobs", 0), "read", None);
        Assert.That(decision.Reason, Is.EqualTo(DenyReason.NotCovered));
        Assert.That(decision.Allowed, Is.False);
    }

    [Test]
    public void A_read_ceiling_still_serves_reads() =>
        Assert.That(Select("GET", "/v1/models", ceiling: "read").Grant?.Name, Is.EqualTo("read"));

    [Test]
    public void An_elevation_grant_is_refused_until_elevated_and_says_which()
    {
        var decision = Select("DELETE", "/admin/cache");
        Assert.That(decision.Reason, Is.EqualTo(DenyReason.ElevationRequired));
        Assert.That(decision.ElevationNeeded, Is.EqualTo("admin"));
    }

    [Test]
    public void An_elevation_grant_is_used_while_elevated() =>
        Assert.That(Select("DELETE", "/admin/cache", elevated: new HashSet<string> { "admin" }).Grant?.Name, Is.EqualTo("admin"));

    [Test]
    public void Elevation_does_not_make_admin_win_over_a_lower_grant() =>
        Assert.That(Select("GET", "/v1/models", elevated: new HashSet<string> { "admin" }).Grant?.Name, Is.EqualTo("read"));

    [Test]
    public void Method_is_case_insensitive() =>
        Assert.That(Select("get", "/v1/models").Grant?.Name, Is.EqualTo("read"));

    [Test]
    public void Deny_beats_allow()
    {
        var service = new Service("s", new Uri("https://x"),
        [
            new Grant("g", "s-g", new RequestRule(new HashSet<string> { "GET" }, [new Regex("^/")], [new Regex("^/secret")])),
        ]);
        Assert.That(GrantSelector.Select(service, new("GET", "/secret/x", 0), null, None).Allowed, Is.False);
        Assert.That(GrantSelector.Select(service, new("GET", "/public", 0), null, None).Allowed, Is.True);
    }

    [Test]
    public void Body_over_the_limit_is_not_covered()
    {
        var service = new Service("s", new Uri("https://x"),
            [new Grant("g", "s-g", new RequestRule(new HashSet<string> { "POST" }, [new Regex("^/")], MaxBodyBytes: 10))]);
        Assert.That(GrantSelector.Select(service, new("POST", "/", 11), null, None).Allowed, Is.False);
        Assert.That(GrantSelector.Select(service, new("POST", "/", 10), null, None).Allowed, Is.True);
    }

    [TestCase("/v1/../admin")]
    [TestCase("/v1/%2e%2e/admin")]
    [TestCase("/v1/%2E%2E/admin")]
    [TestCase("/v1%2fmodels")]
    [TestCase("/v1/%252e%252e/admin")]
    [TestCase("/v1\\models")]
    [TestCase("//evil.example/v1")]
    [TestCase("/v1/./models")]
    [TestCase("v1/models")]
    [TestCase("")]
    public void Suspicious_paths_are_refused_before_any_rule(string path) =>
        Assert.That(Select("GET", path).Reason, Is.EqualTo(DenyReason.SuspiciousPath));

    [TestCase("/v1/models")]
    [TestCase("/v1/models?filter=a%2Fb")]
    [TestCase("/v1/status?x=..")]
    public void Ordinary_paths_pass_the_guard(string path) =>
        Assert.That(PathGuard.IsClean(path), Is.True);
}
