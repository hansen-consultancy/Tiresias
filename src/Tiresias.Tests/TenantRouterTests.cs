using Tiresias.Client;

namespace Tiresias.Tests;

public class TenantRouterTests
{
    static readonly TenantServices Personal = new("personal", new HashSet<string> { "llm", "nuget", "shared" });
    static readonly TenantServices Customer = new("customer", new HashSet<string> { "sqlprod", "raven", "shared" });
    static readonly TenantServices[] Both = [Personal, Customer];

    [TestCase("llm", ExpectedResult = "personal")]
    [TestCase("sqlprod", ExpectedResult = "customer")]
    public string? A_service_held_by_one_tenant_picks_it(string service) =>
        TenantRouter.Resolve(Both, service, null).Tenant;

    [Test]
    public void A_service_held_by_two_tenants_is_never_guessed()
    {
        var choice = TenantRouter.Resolve(Both, "shared", null);
        Assert.That(choice.Tenant, Is.Null);
        Assert.That(choice.Error, Does.Contain("personal, customer").And.Contain("--tenant"));
    }

    [Test]
    public void The_tenant_option_settles_an_ambiguous_service() =>
        Assert.That(TenantRouter.Resolve(Both, "shared", "customer").Tenant, Is.EqualTo("customer"));

    [Test]
    public void The_tenant_option_must_name_a_tenant_that_holds_the_service()
    {
        Assert.That(TenantRouter.Resolve(Both, "llm", "customer").Error, Is.EqualTo("Tenant 'customer' has no service 'llm'."));
        Assert.That(TenantRouter.Resolve(Both, null, "work").Error, Does.StartWith("No tenant 'work'"));
    }

    [Test]
    public void An_unknown_service_with_several_tenants_is_an_error() =>
        Assert.That(TenantRouter.Resolve(Both, "nope", null).Error, Does.StartWith("No tenant has a service 'nope'"));

    [Test]
    public void A_command_about_no_service_needs_the_option_only_when_there_is_a_choice()
    {
        Assert.That(TenantRouter.Resolve([Personal], null, null).Tenant, Is.EqualTo("personal"));
        Assert.That(TenantRouter.Resolve(Both, null, null).Error, Does.Contain("pass --tenant"));
        Assert.That(TenantRouter.Resolve(Both, null, "personal").Tenant, Is.EqualTo("personal"));
    }

    [Test]
    public void With_one_tenant_even_an_unknown_service_goes_there_and_fails_on_its_vault() =>
        Assert.That(TenantRouter.Resolve([Personal], "nope", null).Tenant, Is.EqualTo("personal"));

    [Test]
    public void Not_enrolled_is_its_own_error() =>
        Assert.That(TenantRouter.Resolve([], "llm", null).Error, Does.StartWith("Not enrolled"));
}
