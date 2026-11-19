using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class PolicyChangePlannerTests
{
    static Service Llm(VaultDocument vault) => vault.FindService("llm")!;

    [Test]
    public void Saving_an_approved_service_unchanged_is_empty()
    {
        using var vault = TestVault.Create();
        var change = PolicyChangePlanner.Plan(vault.Document, [Llm(vault.Document)], []);
        Assert.That(change.IsEmpty, Is.True);
    }

    [Test]
    public void A_new_upstream_shows_both_and_rebinds_every_secret_of_the_service()
    {
        using var vault = TestVault.Create();
        var moved = Llm(vault.Document) with { Upstream = new Uri("https://llm2.example/") };

        var change = PolicyChangePlanner.Plan(vault.Document, [moved], []);

        Assert.That(change.Lines, Is.EqualTo(new[]
        {
            "Change service llm",
            "  - upstream https://llm.example/",
            "  + upstream https://llm2.example/",
        }));
        Assert.That(change.Rebind, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin" }));
        Assert.That(change.Next.FindService("llm")!.Upstream, Is.EqualTo(moved.Upstream));
    }

    [Test]
    public void Reordered_grants_are_a_change_because_ceilings_are_positional()
    {
        using var vault = TestVault.Create();
        var llm = Llm(vault.Document);
        var reordered = llm with { Grants = [llm.Grants[1], llm.Grants[0], llm.Grants[2]] };

        var change = PolicyChangePlanner.Plan(vault.Document, [reordered], []);

        Assert.That(change.Lines, Has.Some.StartsWith("  + grant 1. write"));
        Assert.That(change.Rebind, Is.EquivalentTo(new[] { "llm-read", "llm-write" }));
    }

    [Test]
    public void A_new_service_on_a_shared_secret_rebinds_only_that_secret()
    {
        using var vault = TestVault.Create();
        var mirror = new Service("mirror", new Uri("https://mirror.example/"),
            [new Grant("read", "llm-read", new RequestRule(new HashSet<string> { "GET" }, [VaultFile.Compile("^/")], [], null))]);

        var change = PolicyChangePlanner.Plan(vault.Document, [mirror], []);

        Assert.That(change.Lines, Is.EqualTo(new[]
        {
            "Add service mirror",
            "  + upstream https://mirror.example/",
            "  + grant 1. read: secret llm-read, GET ^/",
        }));
        Assert.That(change.Rebind, Is.EqualTo(new[] { "llm-read" }));
    }

    [Test]
    public void Removing_a_service_rebinds_its_secrets_to_what_is_left()
    {
        using var vault = TestVault.Create();
        var change = PolicyChangePlanner.Plan(vault.Document, [], ["llm"]);

        Assert.That(change.Lines[0], Is.EqualTo("Remove service llm"));
        Assert.That(change.Next.Services, Is.Empty);
        Assert.That(change.Next.Secrets, Has.Count.EqualTo(3), "secrets stay");
        Assert.That(change.Rebind, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin" }));
    }

    [Test]
    public void Removing_a_service_that_is_not_there_is_empty()
    {
        using var vault = TestVault.Create();
        Assert.That(PolicyChangePlanner.Plan(vault.Document, [], ["nope"]).IsEmpty, Is.True);
    }

    [Test]
    public void Saving_a_service_whose_secrets_are_unbound_approves_it_as_it_is()
    {
        using var vault = TestVault.CreateUnbound();
        var change = PolicyChangePlanner.Plan(vault.Document, [Llm(vault.Document)], []);

        Assert.That(change.Lines[0], Is.EqualTo("Approve service llm as it is"));
        Assert.That(change.Rebind, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin" }));
    }

    [Test]
    public void Saving_a_service_after_an_unapproved_edit_approves_what_is_on_disk()
    {
        using var vault = TestVault.Create();
        var edited = vault.Document with { Services = [Llm(vault.Document) with { Upstream = new Uri("https://attacker.example/") }] };

        var change = PolicyChangePlanner.Plan(edited, [Llm(edited)], []);

        Assert.That(change.Lines, Has.Some.EqualTo("    upstream https://attacker.example/"), "the user sees what they approve");
        Assert.That(change.Rebind, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin" }));
    }

    [Test]
    public void Unbound_secrets_the_change_does_not_touch_stay_unbound()
    {
        using var vault = TestVault.CreateUnbound();
        var mirror = new Service("mirror", new Uri("https://mirror.example/"),
            [new Grant("read", "llm-read", new RequestRule(new HashSet<string> { "GET" }, [VaultFile.Compile("^/")], [], null))]);

        var change = PolicyChangePlanner.Plan(vault.Document, [mirror], []);

        Assert.That(change.Rebind, Is.EqualTo(new[] { "llm-read" }));
    }

    [Test]
    public void The_lines_never_hold_a_value()
    {
        using var vault = TestVault.Create();
        var change = PolicyChangePlanner.Plan(vault.Document, [], ["llm"]);
        Assert.That(string.Join("\n", change.Lines), Does.Not.Contain("sk-"));
    }

    [Test]
    public void A_service_using_a_missing_secret_is_refused()
    {
        using var vault = TestVault.Create();
        var orphan = new Service("x", new Uri("https://x.example/"),
            [new Grant("read", "nope", new RequestRule(new HashSet<string> { "GET" }, [VaultFile.Compile("^/")], [], null))]);
        Assert.That(() => PolicyChangePlanner.Plan(vault.Document, [orphan], []),
            Throws.InvalidOperationException.With.Message.Contains("nope"));
    }

    [Test]
    public void Migration_binds_every_unbound_secret_as_it_is_and_changes_no_service()
    {
        using var vault = TestVault.CreateWith(tpm => ([SecretEnvelope.Seal("spare", 1, "x"u8, [tpm])], []));
        var unbound = vault.Document with { Secrets = [.. vault.Document.Secrets.Select(s => s.Slug == "llm-read" ? s : s with { PolicyHash = null })] };

        var change = PolicyChangePlanner.Migrate(unbound);

        Assert.That(change.Rebind, Is.EquivalentTo(new[] { "llm-write", "llm-admin", "spare" }));
        Assert.That(change.Lines[0], Is.EqualTo("Approve service llm as it is"));
        Assert.That(change.Lines[^1], Is.EqualTo("Keep secret spare for later: no service uses it"));
        Assert.That(change.Next.Services, Is.EqualTo(unbound.Services));
        Assert.That(PolicyChangePlanner.Replan(unbound, change).Rebind, Is.EqualTo(change.Rebind), "Approve plans it the same way again");
    }

    [Test]
    public void Migrating_a_bound_vault_is_empty()
    {
        using var vault = TestVault.Create();
        Assert.That(PolicyChangePlanner.Migrate(vault.Document).IsEmpty, Is.True);
    }
}
