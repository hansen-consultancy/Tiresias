using Tiresias.Access;
using Tiresias.Audit;
using Tiresias.Broker;
using Tiresias.Leases;
using Tiresias.Policy;
using Tiresias.Transport;
using Tiresias.Crypto;
using Tiresias.Vault;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class BrokerStateTests
{
    // 09:00 in Brussels (UTC+1 in November): the hard cap is 19:00, ten hours on.
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 8, 0, 0, TimeSpan.Zero);

    TestVault vault = null!;
    Key identity = null!;
    ManualTime time = null!;
    string auditPath = "";
    BrokerState state = null!;

    [SetUp]
    public void SetUp()
    {
        vault = TestVault.Create();
        identity = Key.Create(SignatureAlgorithm.Ed25519);
        time = new ManualTime(T0);
        auditPath = Path.Combine(Path.GetTempPath(), $"tir-state-{Guid.NewGuid():N}.jsonl");
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
        var (result, refusal) = state.Seal(offer.LeaseId, vault.SealTo(offer), vault.ApprovalKey(offer.LeaseId));
        Assert.That(refusal, Is.Null);
        Assert.That(result!.Rejected, Is.Empty);
        return offer;
    }

    string Mint(string? ceiling = null)
    {
        var (minted, refusal) = state.Mint(vault.MintApproval(new AccessRequest("claude:test", null, "llm", ceiling, "testing", TimeSpan.FromHours(1)), time.GetUtcNow()));
        Assert.That(refusal, Is.Null);
        return minted!.Token;
    }

    static BrokeredRequest Get(string path) => new("GET", path, 0);

    string[] AuditLines() => File.ReadAllLines(auditPath);

    [Test]
    public void Without_a_lease_every_request_is_refused_as_no_lease()
    {
        var (allowed, refusal) = state.Authorize("Bearer tirph_llm_x", "llm", Get("/v1/models"));
        Assert.That(allowed, Is.Null);
        Assert.That(refusal, Is.EqualTo(new Refusal(503, "no-lease")));
        Assert.That(AuditLines(), Has.Exactly(1).Contains("\"kind\":\"Deny\""));
    }

    [Test]
    public void The_lease_offer_is_signed_by_the_broker_identity()
    {
        var (offer, signature) = state.BeginLease("laptop");
        Assert.That(offer.Verify(identity.PublicKey, signature), Is.True);
        Assert.That(offer.HardCapAt, Is.EqualTo(T0.AddHours(10)));
    }

    [Test]
    public void An_allowed_request_gets_the_least_privileged_secret_once()
    {
        OpenLease();
        var token = Mint();

        var (allowed, refusal) = state.Authorize($"Bearer {token}", "llm", Get("/v1/models?page=2"));
        Assert.That(refusal, Is.Null);
        using (allowed)
        {
            Assert.That(allowed!.Grant.Name, Is.EqualTo("read"));
            Assert.That(allowed.TakeSecret(), Is.EqualTo("Bearer sk-read"));
            Assert.That(allowed.TakeSecret(), Is.EqualTo(new string('\0', "Bearer sk-read".Length)), "zeroed after first use");
            allowed.Complete(200);
        }

        var lines = AuditLines();
        Assert.That(lines, Has.Exactly(1).Contains("\"kind\":\"Allow\""));
        Assert.That(lines.Single(l => l.Contains("\"kind\":\"Allow\"", StringComparison.Ordinal)), Does.Contain("\"path\":\"/v1/models\"").And.Contain("\"status\":200"));
        Assert.That(string.Join("\n", lines), Does.Not.Contain("sk-read").And.Not.Contain(token));
        Assert.That(AuditLog.Verify(auditPath), Is.Null);
    }

    [Test]
    public void Disposing_without_completing_still_writes_exactly_one_allow_record()
    {
        OpenLease();
        var token = Mint();
        state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Allowed!.Dispose();
        Assert.That(AuditLines(), Has.Exactly(1).Contains("\"kind\":\"Allow\"").And.Contains("aborted"));
    }

    [Test]
    public void The_ceiling_refuses_a_write_even_though_a_write_grant_exists()
    {
        OpenLease();
        var token = Mint(ceiling: "read");
        var (_, refusal) = state.Authorize($"Bearer {token}", "llm", new("POST", "/v1/chat", 10));
        Assert.That(refusal, Is.EqualTo(new Refusal(403, "not-covered")));
    }

    [Test]
    public void An_elevated_grant_is_refused_by_name_until_elevated()
    {
        OpenLease();
        var token = Mint();
        var delete = new BrokeredRequest("DELETE", "/v1/models/x", 0);

        Assert.That(state.Authorize($"Bearer {token}", "llm", delete).Refusal, Is.EqualTo(new Refusal(403, "elevation-required", "admin")));

        var (expires, refusal) = state.Elevate(vault.ElevateApproval("llm", "admin", TimeSpan.FromMinutes(15), time.GetUtcNow()));
        Assert.That(refusal, Is.Null);
        Assert.That(expires, Is.EqualTo(T0.AddMinutes(15)));
        using var allowed = state.Authorize($"Bearer {token}", "llm", delete).Allowed;
        Assert.That(allowed!.Grant.Name, Is.EqualTo("admin"));
    }

    [Test]
    public void Only_elevation_grants_can_be_elevated()
    {
        OpenLease();
        Assert.That(state.Elevate(vault.ElevateApproval("llm", "read", TimeSpan.FromMinutes(5), time.GetUtcNow())).Refusal?.Reason, Is.EqualTo("not-elevatable"));
    }

    [Test]
    public void A_placeholder_works_only_for_its_own_service()
    {
        OpenLease();
        var token = Mint();
        Assert.That(state.Authorize($"Bearer {token}", "github", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("wrong-service"));
    }

    [Test]
    public void A_suspicious_path_is_refused()
    {
        OpenLease();
        var token = Mint();
        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models/%2e%2e/admin")).Refusal?.Reason, Is.EqualTo("suspicious-path"));
    }

    [Test]
    public void A_dek_sealed_for_another_lease_or_unknown_secret_is_rejected()
    {
        var (first, _) = state.BeginLease("laptop");
        var stale = vault.SealTo(first);
        var (second, _) = state.BeginLease("laptop");

        var (result, _) = state.Seal(second.LeaseId, new Dictionary<string, byte[]>(stale) { ["nope"] = [1, 2, 3] }, vault.ApprovalKey(second.LeaseId));
        Assert.That(result!.Accepted, Is.Empty);
        Assert.That(result.Rejected, Is.EquivalentTo(new[] { "llm-read", "llm-write", "llm-admin", "nope" }));
    }

    [Test]
    public void Sealing_to_a_lease_that_is_not_current_is_a_conflict()
    {
        OpenLease();
        Assert.That(state.Seal("other", new Dictionary<string, byte[]>(), vault.ApprovalKey("other")).Refusal?.Status, Is.EqualTo(409));
    }

    [Test]
    public void An_invalid_access_request_is_refused_with_its_problems()
    {
        OpenLease();
        var (_, refusal) = state.Mint(vault.MintApproval(new AccessRequest("claude:test", null, "llm", null, "", TimeSpan.FromHours(1)), time.GetUtcNow()));
        Assert.That(refusal!.Status, Is.EqualTo(400));
        Assert.That(refusal.Problems, Has.Some.Contains("purpose"));
    }

    [Test]
    public void The_hard_cap_zeroes_the_deks_and_revokes_placeholders()
    {
        OpenLease();
        var token = Mint();
        var deks = state.LeasedDeks();
        Assert.That(deks, Has.Count.EqualTo(3));

        time.Now = T0.AddHours(10);
        state.Tick();

        Assert.That(deks.All(d => d.All(b => b == 0)), Is.True);
        Assert.That(state.LeasedDeks(), Is.Empty);
        Assert.That(AuditLines(), Has.Exactly(1).Contains("\"kind\":\"LeaseEnd\"").And.Contains("HardCap"));
        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("no-lease"));
    }

    [Test]
    public void A_lost_heartbeat_ends_the_lease_and_a_heartbeat_in_time_keeps_it()
    {
        var offer = OpenLease();
        time.Now = T0.AddMinutes(14);
        Assert.That(state.Heartbeat(offer.LeaseId), Is.Null);
        time.Now = T0.AddMinutes(30);
        Assert.That(state.Heartbeat(offer.LeaseId)?.Reason, Is.EqualTo("no-lease"));
    }

    [Test]
    public void A_lease_ends_when_the_device_that_opened_it_is_no_longer_trusted()
    {
        OpenLease();
        var token = Mint();

        Assert.That(state.EndLeaseOfUntrustedDevice(device => device != "laptop"), Is.True);

        Assert.That(state.LeasedDeks(), Is.Empty);
        Assert.That(AuditLines(), Has.Exactly(1).Contains("\"kind\":\"LeaseEnd\"").And.Contains("device-revoked"));
        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("no-lease"));
    }

    [Test]
    public void A_lease_of_a_still_trusted_device_survives_a_trust_change()
    {
        OpenLease();
        Assert.That(state.EndLeaseOfUntrustedDevice(device => device == "laptop"), Is.False);
        Assert.That(state.LeasedDeks(), Has.Count.EqualTo(3));
    }

    [Test]
    public void Ending_a_lease_kills_its_placeholders_for_good()
    {
        OpenLease();
        var token = Mint();
        state.End();
        OpenLease();
        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("unknown-placeholder"));
    }

    [Test]
    public void A_reloaded_vault_keeps_the_lease_its_placeholders_and_the_deks_that_still_open()
    {
        OpenLease();
        var token = Mint();
        var dropped = state.LeasedDeks().ToArray();
        var added = SecretEnvelope.Seal("httpbin", 1, "Bearer hb"u8, [vault.Tpm]);
        var reloaded = vault.Document with
        {
            Secrets = [.. vault.Document.Secrets.Where(s => s.Slug != "llm-admin"), added],
            Services = [.. vault.Document.Services, new Service("httpbin", new Uri("https://httpbin.example/"), [])],
        };

        var reload = state.ReplaceVault(reloaded);

        Assert.That(reload.Unleased, Is.EqualTo(new[] { "httpbin" }));
        Assert.That(state.LeasedDeks(), Has.Count.EqualTo(2), "the removed secret's DEK is gone");
        Assert.That(dropped.Count(d => d.All(b => b == 0)), Is.EqualTo(1), "and zeroed");
        using var allowed = state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Allowed;
        Assert.That(allowed!.TakeSecret(), Is.EqualTo("Bearer sk-read"));
    }

    [Test]
    public void Restoring_an_older_vault_mid_lease_is_refused_and_the_newer_one_kept()
    {
        OpenLease();
        var token = Mint();
        var newer = SecretEnvelope.Seal("llm-read", 2, "Bearer sk-read-2"u8, [vault.Tpm], PolicyBinding.Hash(vault.Document, "llm-read"));
        state.ReplaceVault(vault.Document with { Secrets = [.. vault.Document.Secrets.Where(s => s.Slug != "llm-read"), newer] });

        var reload = state.ReplaceVault(vault.Document);

        Assert.That(reload.Refused, Is.True);
        Assert.That(reload.RolledBack, Is.EqualTo(new[] { "llm-read" }));
        Assert.That(AuditLines(), Has.Exactly(1).Contains("secret-rolled-back: llm-read"));
        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("secret-not-leased"),
            "still the newer vault, waiting for its DEK");
    }

    [Test]
    public void A_new_lease_starts_its_own_high_water_mark()
    {
        OpenLease();
        var newer = SecretEnvelope.Seal("llm-read", 2, "Bearer sk-read-2"u8, [vault.Tpm], PolicyBinding.Hash(vault.Document, "llm-read"));
        state.ReplaceVault(vault.Document with { Secrets = [.. vault.Document.Secrets.Where(s => s.Slug != "llm-read"), newer] });
        state.End();

        Assert.That(state.ReplaceVault(vault.Document).Refused, Is.False, "without a lease there is nothing to compare with");
    }

    [Test]
    public void A_re_sealed_secret_loses_its_old_dek_until_the_new_one_is_sealed()
    {
        var offer = OpenLease();
        var token = Mint();
        var resealed = SecretEnvelope.Seal("llm-read", 2, "Bearer sk-read-2"u8, [vault.Tpm], PolicyBinding.Hash(vault.Document, "llm-read"));
        var reloaded = vault.Document with { Secrets = [.. vault.Document.Secrets.Where(s => s.Slug != "llm-read"), resealed] };

        Assert.That(state.ReplaceVault(reloaded).Unleased, Is.EqualTo(new[] { "llm-read" }));
        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("secret-not-leased"));

        var dek = SecretEnvelope.UnwrapDek(resealed, vault.Tpm)!;
        var (result, _) = state.Seal(offer.LeaseId, new Dictionary<string, byte[]>
            { ["llm-read"] = vault.SealDek(offer, "llm-read", dek) }, vault.ApprovalKey(offer.LeaseId));
        Assert.That(result!.Accepted, Is.EqualTo(new[] { "llm-read" }));
        using var allowed = state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Allowed;
        Assert.That(allowed!.TakeSecret(), Is.EqualTo("Bearer sk-read-2"));
    }

    [Test]
    public void A_removed_service_revokes_its_placeholders()
    {
        OpenLease();
        var token = Mint();

        // Removed as the app removes it: each secret rebound to what is left (no service).
        var removed = vault.Document with { Services = [] };
        state.ReplaceVault(removed with { Secrets = [.. removed.Secrets.Select(s =>
            SecretEnvelope.Rebind(s, SecretEnvelope.UnwrapDek(s, vault.Tpm)!, PolicyBinding.Hash(removed, s.Slug), [vault.Tpm])!)] });

        Assert.That(state.Authorize($"Bearer {token}", "llm", Get("/v1/models")).Refusal?.Reason, Is.EqualTo("unknown-placeholder"));
        Assert.That(AuditLines(), Has.Exactly(1).Contains("\"kind\":\"PlaceholderRevoked\"").And.Contains("policy-changed"));
    }

    [Test]
    public void Without_a_lease_a_reload_has_nothing_to_seal() =>
        Assert.That(state.ReplaceVault(vault.Document).Unleased, Is.Empty);
}
