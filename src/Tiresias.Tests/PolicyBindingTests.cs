using System.Text;
using Tiresias.Access;
using Tiresias.Audit;
using Tiresias.Broker;
using Tiresias.Leases;
using Tiresias.Policy;
using Tiresias.Transport;
using Tiresias.Vault;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class PolicyBindingTests
{
    static readonly VaultDocument Policy = new([],
    [
        new Service("llm", new Uri("https://llm.example/"),
        [
            new Grant("read", "llm-read", new(new HashSet<string> { "GET" }, [VaultFile.Compile("^/v1/models")])),
            new Grant("admin", "llm-admin", new(new HashSet<string> { "DELETE", "POST" }, [VaultFile.Compile("^/v1/")], [VaultFile.Compile("^/v1/billing")], 1024), RequiresElevation: true),
        ]),
        new Service("other", new Uri("https://other.example/"), [new Grant("read", "other-read", new(new HashSet<string> { "GET" }, [VaultFile.Compile("^/")]))]),
    ]);

    static Service Llm => Policy.Services[0];

    static VaultDocument WithLlm(Service llm) => Policy with { Services = [llm, Policy.Services[1]] };

    static VaultDocument WithGrant(int index, Func<Grant, Grant> change) =>
        WithLlm(Llm with { Grants = [.. Llm.Grants.Select((g, i) => i == index ? change(g) : g)] });

    static bool SameHash(VaultDocument a, VaultDocument b, string slug) =>
        PolicyBinding.Hash(a, slug).AsSpan().SequenceEqual(PolicyBinding.Hash(b, slug));

    [Test]
    public void The_canonical_form_is_pinned() =>
        Assert.That(Encoding.UTF8.GetString(PolicyBinding.For(Policy, "llm-admin")), Is.EqualTo(
            """["tiresias/v1/policy-binding",["llm","https://llm.example/",1,"admin","llm-admin",["DELETE","POST"],["^/v1/"],["^/v1/billing"],1024,true,false]]"""));

    [Test]
    public void A_secret_no_grant_uses_binds_to_the_empty_policy() =>
        Assert.That(Encoding.UTF8.GetString(PolicyBinding.For(Policy, "nope")), Is.EqualTo("""["tiresias/v1/policy-binding"]"""));

    static IEnumerable<TestCaseData> Changes()
    {
        yield return new TestCaseData(WithLlm(Llm with { Upstream = new Uri("https://attacker.example/") })).SetName("upstream");
        yield return new TestCaseData(WithGrant(0, g => g with { Rule = g.Rule with { Methods = new HashSet<string> { "GET", "POST" } } })).SetName("method");
        yield return new TestCaseData(WithGrant(0, g => g with { Rule = g.Rule with { Allow = [VaultFile.Compile("^/")] } })).SetName("allow");
        yield return new TestCaseData(WithGrant(0, g => g with { Rule = g.Rule with { Deny = [VaultFile.Compile("^/x")] } })).SetName("deny");
        yield return new TestCaseData(WithGrant(0, g => g with { Rule = g.Rule with { MaxBodyBytes = 1 } })).SetName("max body");
        yield return new TestCaseData(WithGrant(0, g => g with { RequiresElevation = true })).SetName("elevation");
        yield return new TestCaseData(WithGrant(0, g => g with { IssuesLogins = true })).SetName("logins");
        yield return new TestCaseData(WithGrant(0, g => g with { Name = "write" })).SetName("grant name");
        yield return new TestCaseData(WithLlm(Llm with { Grants = [Llm.Grants[1], Llm.Grants[0]] })).SetName("grant order");
        yield return new TestCaseData(WithGrant(1, g => g with { SecretSlug = "llm-read" })).SetName("another grant points at the secret");
        yield return new TestCaseData(WithGrant(0, g => g with { SecretSlug = "llm-admin" })).SetName("the grant points elsewhere");
        yield return new TestCaseData(WithLlm(Llm with { Slug = "renamed" })).SetName("service slug");
    }

    [TestCaseSource(nameof(Changes))]
    public void Any_change_to_a_grant_using_the_secret_changes_its_binding(VaultDocument changed) =>
        Assert.That(SameHash(Policy, changed, "llm-read"), Is.False);

    [Test]
    public void Changing_another_service_leaves_the_binding_alone()
    {
        var changed = Policy with { Services = [Llm, Policy.Services[1] with { Upstream = new Uri("https://elsewhere.example/") }] };
        Assert.That(SameHash(Policy, changed, "llm-read"), Is.True);
    }

    [Test]
    public void The_service_hash_follows_any_change_to_the_service()
    {
        Assert.That(PolicyBinding.ServiceHash(Llm), Is.EqualTo(PolicyBinding.ServiceHash(Llm with { })));
        Assert.That(PolicyBinding.ServiceHash(Llm), Is.Not.EqualTo(PolicyBinding.ServiceHash(Llm with { Upstream = new Uri("https://attacker.example/") })));
    }
}

public class BoundSecretEnvelopeTests
{
    readonly Key tpmKey = Key.Create(KeyAgreementAlgorithm.X25519);

    [OneTimeTearDown]
    public void TearDown() => tpmKey.Dispose();

    [Test]
    public void A_bound_secret_opens_only_under_its_policy_hash()
    {
        var tpm = X25519KeyWrapper.ForKey("tpm", tpmKey);
        var hash = new byte[32];
        hash[0] = 1;
        var secret = SecretEnvelope.Seal("s", 1, "value"u8, [tpm], hash);
        var dek = SecretEnvelope.UnwrapDek(secret, tpm)!;

        Assert.That(secret.BoundToPolicy, Is.True);
        Assert.That(SecretEnvelope.Open(secret, dek, hash), Is.EqualTo("value"u8.ToArray()));
        Assert.That(SecretEnvelope.Open(secret, dek, new byte[32]), Is.Null, "another policy");
        Assert.That(SecretEnvelope.Open(secret, dek), Is.Null, "no policy");
        Assert.That(SecretEnvelope.Open(secret with { BoundToPolicy = false }, dek), Is.Null, "the flag cleared on disk");
    }

    [Test]
    public void An_unbound_secret_ignores_the_policy_hash()
    {
        var tpm = X25519KeyWrapper.ForKey("tpm", tpmKey);
        var secret = SecretEnvelope.Seal("s", 1, "value"u8, [tpm]);
        var dek = SecretEnvelope.UnwrapDek(secret, tpm)!;
        Assert.That(SecretEnvelope.Open(secret, dek, new byte[32]), Is.EqualTo("value"u8.ToArray()));
    }

    [Test]
    public void The_vault_file_keeps_the_flag_and_stays_version_1_without_it()
    {
        using var vault = TestVault.CreateBound();
        using var plain = TestVault.Create();
        var dir = Directory.CreateTempSubdirectory("tir-bound-").FullName;
        try
        {
            var boundPath = Path.Combine(dir, "bound.json");
            var plainPath = Path.Combine(dir, "plain.json");
            VaultFile.Save(boundPath, vault.Document);
            VaultFile.Save(plainPath, plain.Document);

            Assert.That(VaultFile.Load(boundPath).Secrets.All(s => s.BoundToPolicy), Is.True);
            Assert.That(File.ReadAllText(boundPath), Does.Contain("\"version\": 2"));
            Assert.That(File.ReadAllText(plainPath), Does.Contain("\"version\": 1").And.Not.Contain("boundToPolicy"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public class BrokerPolicyTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 8, 0, 0, TimeSpan.Zero);

    TestVault vault = null!;
    Key identity = null!;
    ManualTime time = null!;
    string auditPath = "";
    BrokerState state = null!;

    [SetUp]
    public void SetUp()
    {
        vault = TestVault.CreateBound();
        identity = Key.Create(SignatureAlgorithm.Ed25519);
        time = new ManualTime(T0);
        auditPath = Path.Combine(Path.GetTempPath(), $"tir-policy-{Guid.NewGuid():N}.jsonl");
        state = new BrokerState(vault.Document, LeaseTerms.Workday(TimeZoneInfo.FindSystemTimeZoneById("Europe/Brussels")),
            new AuditLog(auditPath, time), identity, time);
    }

    [TearDown]
    public void TearDown()
    {
        state.Dispose();
        identity.Dispose();
        vault.Dispose();
        File.Delete(auditPath);
    }

    LeaseOffer OpenLease()
    {
        var (offer, _) = state.BeginLease("laptop");
        Assert.That(state.Seal(offer.LeaseId, vault.SealTo(offer)).Result!.Rejected, Is.Empty);
        return offer;
    }

    string Mint(string service = "llm")
    {
        var (minted, refusal) = state.Mint(new AccessRequest("claude:test", null, service, null, "testing", TimeSpan.FromHours(1)));
        Assert.That(refusal, Is.Null);
        return minted!.Token;
    }

    Refusal? Get(string token, string path = "/v1/models")
    {
        var (allowed, refusal) = state.Authorize($"Bearer {token}", "llm", new("GET", path, 0));
        allowed?.Dispose();
        return refusal;
    }

    VaultDocument Tampered(Func<Service, Service> change) =>
        vault.Document with { Services = [change(vault.Document.Services[0])] };

    [Test]
    public void A_bound_vault_serves_as_usual()
    {
        OpenLease();
        var (allowed, refusal) = state.Authorize($"Bearer {Mint()}", "llm", new("GET", "/v1/models", 0));
        Assert.That(refusal, Is.Null);
        using (allowed)
            Assert.That(allowed!.TakeSecret(), Is.EqualTo("Bearer sk-read"));
    }

    [Test]
    public void A_reload_that_changes_a_bound_policy_is_refused_and_the_old_one_kept()
    {
        OpenLease();
        var token = Mint();

        var reload = state.ReplaceVault(Tampered(s => s with { Upstream = new Uri("https://attacker.example/") }));

        Assert.That(reload.Refused, Is.True);
        Assert.That(reload.Unapproved, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin" }));
        var (allowed, _) = state.Authorize($"Bearer {token}", "llm", new("GET", "/v1/models", 0));
        using (allowed)
            Assert.That(allowed!.Service.Upstream, Is.EqualTo(new Uri("https://llm.example/")), "still the approved upstream");
        Assert.That(File.ReadAllText(auditPath), Does.Contain("policy-not-approved: llm-read"));
    }

    [Test]
    public void A_widened_rule_is_refused_too()
    {
        OpenLease();
        var reload = state.ReplaceVault(Tampered(s => s with { Grants = [s.Grants[0] with { Rule = s.Grants[0].Rule with { Allow = [VaultFile.Compile("^/")] } }, .. s.Grants.Skip(1)] }));
        Assert.That(reload.Unapproved, Is.EqualTo(new[] { "llm-read" }));
    }

    [Test]
    public void A_broker_started_on_a_tampered_policy_refuses_the_deks()
    {
        using var tampered = new BrokerState(Tampered(s => s with { Upstream = new Uri("https://attacker.example/") }),
            LeaseTerms.Workday(TimeZoneInfo.FindSystemTimeZoneById("Europe/Brussels")), new AuditLog(auditPath, time), Key.Create(SignatureAlgorithm.Ed25519), time);
        var (offer, _) = tampered.BeginLease("laptop");
        Assert.That(tampered.Seal(offer.LeaseId, vault.SealTo(offer)).Result!.Accepted, Is.Empty);
    }

    [Test]
    public void A_re_sealed_secret_under_a_new_policy_is_an_approved_change()
    {
        OpenLease();
        var changed = Tampered(s => s with { Upstream = new Uri("https://llm2.example/") });
        var approved = changed with { Secrets = [.. changed.Secrets.Select(old =>
        {
            var dek = SecretEnvelope.UnwrapDek(old, vault.Tpm)!;
            var value = SecretEnvelope.Open(old, dek, PolicyBinding.Hash(vault.Document, old.Slug))!;
            return SecretEnvelope.Seal(old.Slug, 2, value, [vault.Tpm], PolicyBinding.Hash(changed, old.Slug));
        })] };

        var reload = state.ReplaceVault(approved);

        Assert.That(reload.Unapproved, Is.Empty, "re-sealed secrets are not an unapproved change");
        Assert.That(reload.Unleased, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin" }), "their new DEKs must be sealed to the lease");
    }

    [Test]
    public void A_policy_change_retires_the_services_placeholders_and_elevations()
    {
        // Unbound secrets: the change itself is accepted, as for every vault before binding.
        state.Dispose();
        vault.Dispose();
        vault = TestVault.Create();
        state = new BrokerState(vault.Document, LeaseTerms.Workday(TimeZoneInfo.FindSystemTimeZoneById("Europe/Brussels")),
            new AuditLog(auditPath, time), Key.Create(SignatureAlgorithm.Ed25519), time);
        OpenLease();
        var token = Mint();
        state.Elevate("llm", "admin", TimeSpan.FromMinutes(15));

        var reload = state.ReplaceVault(Tampered(s => s with { Upstream = new Uri("https://llm2.example/") }));

        Assert.That(reload.Refused, Is.False);
        Assert.That(Get(token)?.Reason, Is.EqualTo("unknown-placeholder"));
        var fresh = Mint();
        Assert.That(state.Authorize($"Bearer {fresh}", "llm", new("DELETE", "/v1/x", 0)).Refusal?.Reason, Is.EqualTo("elevation-required"));
    }

    [Test]
    public void An_unchanged_service_keeps_its_placeholders()
    {
        OpenLease();
        var token = Mint();
        Assert.That(state.ReplaceVault(vault.Document with { }).Refused, Is.False);
        Assert.That(Get(token), Is.Null);
    }
}
