using System.Text.RegularExpressions;
using Tiresias.Access;
using Tiresias.Policy;

namespace Tiresias.Tests;

sealed class ManualTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

public class ConsentTests
{
    static readonly Service Llm = new("llm", new Uri("https://llm.example.com"),
    [
        new Grant("read", "llm-read", new RequestRule(new HashSet<string> { "GET" }, [new Regex("^/")])),
        new Grant("write", "llm-write", new RequestRule(new HashSet<string> { "POST" }, [new Regex("^/")])),
        new Grant("admin", "llm-admin", new RequestRule(new HashSet<string> { "DELETE" }, [new Regex("^/")]), RequiresElevation: true),
    ]);

    static AccessRequest Request(string? ceiling = "read", string purpose = "nightly export", TimeSpan? duration = null) =>
        new("script:export", @"C:\tools\export.exe (pid 4242)", "llm", ceiling, purpose, duration ?? TimeSpan.FromHours(1));

    [Test]
    public void A_complete_request_has_no_problems() =>
        Assert.That(Consent.Validate(Request(), Llm), Is.Empty);

    [Test]
    public void Purpose_is_required() =>
        Assert.That(Consent.Validate(Request(purpose: " "), Llm), Has.Some.Contains("purpose"));

    [Test]
    public void Unknown_ceiling_is_a_problem() =>
        Assert.That(Consent.Validate(Request(ceiling: "superuser"), Llm), Has.Some.Contains("no grant 'superuser'"));

    [TestCase(0)]
    [TestCase(11)]
    public void Duration_out_of_range_is_a_problem(int hours) =>
        Assert.That(Consent.Validate(Request(duration: TimeSpan.FromHours(hours)), Llm), Has.Some.Contains("Duration"));

    [Test]
    public void Read_ceiling_lists_only_read()
    {
        var lines = Consent.Describe(Request(), Llm);
        Assert.That(lines, Has.Some.EqualTo("Grants:       read"));
        Assert.That(lines, Has.Some.EqualTo("Process:      C:\\tools\\export.exe (pid 4242)"));
    }

    [Test]
    public void No_ceiling_lists_every_grant_and_marks_elevation() =>
        Assert.That(Consent.Describe(Request(ceiling: null), Llm), Has.Some.EqualTo("Grants:       read, write, admin (needs elevation)"));
}

public class PlaceholderRegistryTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);

    static AccessRequest Request(TimeSpan duration) =>
        new("claude:test", null, "llm", "read", "test", duration);

    [Test]
    public void Token_has_the_greppable_prefix_and_service_hint() =>
        Assert.That(PlaceholderToken.Mint("llm"), Does.Match("^tirph_llm_[a-z2-7]{26}$"));

    [Test]
    public void Resolves_within_its_lease_and_lifetime()
    {
        var registry = new PlaceholderRegistry(new ManualTime(T0));
        var token = registry.Mint("L1", Request(TimeSpan.FromHours(1)), T0.AddHours(10));
        var (placeholder, rejection) = registry.Resolve(token, "L1");
        Assert.That(rejection, Is.EqualTo(PlaceholderRejection.None));
        Assert.That(placeholder!.Request.Ceiling, Is.EqualTo("read"));
    }

    [Test]
    public void Expires_after_its_requested_duration()
    {
        var time = new ManualTime(T0);
        var registry = new PlaceholderRegistry(time);
        var token = registry.Mint("L1", Request(TimeSpan.FromHours(1)), T0.AddHours(10));
        time.Now = T0.AddHours(1);
        Assert.That(registry.Resolve(token, "L1").Rejection, Is.EqualTo(PlaceholderRejection.Expired));
    }

    [Test]
    public void Never_outlives_the_lease()
    {
        var time = new ManualTime(T0);
        var registry = new PlaceholderRegistry(time);
        var token = registry.Mint("L1", Request(TimeSpan.FromHours(8)), T0.AddHours(2));
        time.Now = T0.AddHours(2);
        Assert.That(registry.Resolve(token, "L1").Rejection, Is.EqualTo(PlaceholderRejection.Expired));
    }

    [Test]
    public void Is_rejected_under_another_lease_or_no_lease()
    {
        var registry = new PlaceholderRegistry(new ManualTime(T0));
        var token = registry.Mint("L1", Request(TimeSpan.FromHours(1)), T0.AddHours(10));
        Assert.That(registry.Resolve(token, "L2").Rejection, Is.EqualTo(PlaceholderRejection.LeaseEnded));
        Assert.That(registry.Resolve(token, null).Rejection, Is.EqualTo(PlaceholderRejection.LeaseEnded));
    }

    [Test]
    public void Revoking_a_lease_forgets_its_placeholders()
    {
        var registry = new PlaceholderRegistry(new ManualTime(T0));
        var a = registry.Mint("L1", Request(TimeSpan.FromHours(1)), T0.AddHours(10));
        var b = registry.Mint("L2", Request(TimeSpan.FromHours(1)), T0.AddHours(10));

        Assert.That(registry.RevokeLease("L1"), Is.EqualTo(1));
        Assert.That(registry.Resolve(a, "L1").Rejection, Is.EqualTo(PlaceholderRejection.Unknown));
        Assert.That(registry.Resolve(b, "L2").Rejection, Is.EqualTo(PlaceholderRejection.None));
    }

    [Test]
    public void An_unknown_token_is_rejected() =>
        Assert.That(new PlaceholderRegistry(new ManualTime(T0)).Resolve("tirph_llm_nope", "L1").Rejection, Is.EqualTo(PlaceholderRejection.Unknown));
}
