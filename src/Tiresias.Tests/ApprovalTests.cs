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

/// <summary>Step-up at the broker (docs/step-up.md): approvals, the approval key, and the broker's checks.</summary>
public class ApprovalTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 8, 0, 0, TimeSpan.Zero);

    static Approval Sample() =>
        new(Approval.MintOp, "L1", "llm", "read", 3600, "claude:test", "testing", null, T0.ToUnixTimeSeconds(), "n1");

    [Test]
    public void The_canonical_form_is_pinned() =>
        Assert.That(Encoding.UTF8.GetString(Sample().Canonical()),
            Is.EqualTo("""["tiresias/v1/approval","mint","L1","llm","read",3600,"claude:test","testing",null,1794902400,"n1"]"""));

    [Test]
    public void Parse_reads_back_only_the_canonical_form()
    {
        Assert.That(Approval.Parse(Sample().Canonical()), Is.EqualTo(Sample()));
        Assert.That(Approval.Parse(Encoding.UTF8.GetBytes(""" ["tiresias/v1/approval","mint","L1","llm","read",3600,"claude:test","testing",null,1794902400,"n1"]""")), Is.Null);
        Assert.That(Approval.Parse("not json"u8.ToArray()), Is.Null);
    }

    [Test]
    public void Changing_any_field_breaks_the_signature()
    {
        using var key = ApprovalKey.Derive(new byte[32], "L1");
        var signed = Sample().Sign(key);
        Assert.That(signed.Verify(key.PublicKey), Is.EqualTo(Sample()));

        Approval[] changed =
        [
            Sample() with { Op = Approval.ElevateOp }, Sample() with { LeaseId = "L2" }, Sample() with { Service = "gh" },
            Sample() with { Grant = null }, Sample() with { Seconds = 36000 }, Sample() with { Consumer = "x" },
            Sample() with { Purpose = "other" }, Sample() with { Observed = "p" }, Sample() with { IssuedAt = 1 }, Sample() with { Nonce = "n2" },
        ];
        foreach (var other in changed)
            Assert.That(new SignedApproval(other.Canonical(), signed.Signature).Verify(key.PublicKey), Is.Null, other.ToString());
    }

    [Test]
    public void The_same_wrap_and_lease_derive_the_same_key_and_another_lease_another()
    {
        static byte[] Sign(byte[] _) => Enumerable.Repeat((byte)7, 256).ToArray();
        using var first = new SignatureDerivedWrapper("hello", Sign);
        using var again = new SignatureDerivedWrapper("hello", Sign);
        using var a = first.ApprovalKey("L1");
        using var b = again.ApprovalKey("L1");
        using var c = first.ApprovalKey("L2");
        Assert.That(ApprovalKey.Public(a), Is.EqualTo(ApprovalKey.Public(b)));
        Assert.That(ApprovalKey.Public(a), Is.Not.EqualTo(ApprovalKey.Public(c)));
    }

    TestVault vault = null!;
    ManualTime time = null!;
    string auditPath = "";
    BrokerState state = null!;
    LeaseOffer offer = null!;

    [SetUp]
    public void SetUp()
    {
        vault = TestVault.Create();
        time = new ManualTime(T0);
        auditPath = Path.Combine(Path.GetTempPath(), $"tir-approval-{Guid.NewGuid():N}.jsonl");
        state = new BrokerState(vault.Document, LeaseTerms.Workday(TimeZoneInfo.FindSystemTimeZoneById("Europe/Brussels")),
            new AuditLog(auditPath, time), Key.Create(SignatureAlgorithm.Ed25519), time);
        offer = state.BeginLease("laptop").Offer;
        Assert.That(state.Seal(offer.LeaseId, vault.SealTo(offer), vault.ApprovalKey(offer.LeaseId)).Result!.Rejected, Is.Empty);
    }

    [TearDown]
    public void TearDown()
    {
        state.Dispose();
        vault.Dispose();
        File.Delete(auditPath);
    }

    static AccessRequest Request(string? ceiling = "read") => new("claude:test", null, "llm", ceiling, "testing", TimeSpan.FromHours(1));

    [Test]
    public void A_mint_elevation_or_token_without_an_approval_is_refused_and_audited()
    {
        Assert.That(state.Mint(null).Refusal, Is.EqualTo(new Refusal(401, "approval-required")));
        Assert.That(state.Elevate(null).Refusal, Is.EqualTo(new Refusal(401, "approval-required")));
        Assert.That(state.AuthorizeToken("llm", "laptop", null).Refusal, Is.EqualTo(new Refusal(401, "approval-required")));
        Assert.That(File.ReadAllLines(auditPath), Has.Exactly(3).Contains("approval-required"));
    }

    [Test]
    public void A_valid_approval_mints_exactly_what_it_names()
    {
        var (minted, refusal) = state.Mint(vault.MintApproval(Request(), T0));
        Assert.That(refusal, Is.Null);
        Assert.That(minted!.ExpiresAt, Is.EqualTo(T0.AddHours(1)));
        var write = state.Authorize($"Bearer {minted.Token}", "llm", new BrokeredRequest("POST", "/v1/chat", 0));
        Assert.That(write.Refusal?.Reason, Is.EqualTo("not-covered"), "the approved ceiling is read");
    }

    [Test]
    public void An_approval_signed_by_another_key_is_refused()
    {
        using var other = ApprovalKey.Derive(new byte[32], offer.LeaseId);
        Assert.That(state.Mint(Approval.ForMint(offer.LeaseId, Request(), T0).Sign(other)).Refusal?.Reason, Is.EqualTo("approval-invalid"));
    }

    [Test]
    public void An_approval_for_another_lease_or_operation_is_refused()
    {
        Assert.That(state.Mint(vault.Approve(Approval.ForMint("other", Request(), T0))).Refusal?.Reason, Is.EqualTo("approval-invalid"));
        Assert.That(state.Elevate(vault.MintApproval(Request(), T0)).Refusal?.Reason, Is.EqualTo("approval-invalid"));
        Assert.That(state.AuthorizeToken("gh", "laptop", vault.TokenApproval("llm", T0)).Refusal?.Reason, Is.EqualTo("approval-invalid"));
    }

    [Test]
    public void A_replayed_or_stale_approval_is_refused()
    {
        var signed = vault.MintApproval(Request(), T0);
        Assert.That(state.Mint(signed).Refusal, Is.Null);
        Assert.That(state.Mint(signed).Refusal?.Reason, Is.EqualTo("approval-replayed"));
        Assert.That(state.Mint(vault.MintApproval(Request(), T0.AddMinutes(-6))).Refusal?.Reason, Is.EqualTo("approval-stale"));
    }

    [Test]
    public void An_elevation_lasts_the_approved_minutes()
    {
        var (expires, refusal) = state.Elevate(vault.ElevateApproval("llm", "admin", TimeSpan.FromMinutes(5), T0));
        Assert.That(refusal, Is.Null);
        Assert.That(expires, Is.EqualTo(T0.AddMinutes(5)));
    }

    [Test]
    public void A_seal_without_an_approval_key_or_with_a_second_one_is_refused()
    {
        Assert.That(state.Seal(offer.LeaseId, vault.SealTo(offer), null).Refusal?.Reason, Is.EqualTo("approval-key-required"));
        using var other = ApprovalKey.Derive(new byte[32], offer.LeaseId);
        Assert.That(state.Seal(offer.LeaseId, new Dictionary<string, byte[]>(), ApprovalKey.Public(other)).Refusal?.Reason,
            Is.EqualTo("approval-key-mismatch"));
    }

    [Test]
    public void A_key_from_a_seal_with_no_valid_dek_approves_nothing()
    {
        // A program with only the device key begins its own lease and names its own key.
        var (own, _) = state.BeginLease("laptop");
        using var forged = ApprovalKey.Derive(new byte[32], own.LeaseId);
        var (result, _) = state.Seal(own.LeaseId, new Dictionary<string, byte[]> { ["llm-read"] = [1, 2, 3] }, ApprovalKey.Public(forged));
        Assert.That(result!.Accepted, Is.Empty);

        Assert.That(state.Mint(Approval.ForMint(own.LeaseId, Request(), T0).Sign(forged)).Refusal?.Reason, Is.EqualTo("approval-invalid"));
    }

    [Test]
    public void Deks_sealed_with_one_approval_key_dont_vouch_for_another()
    {
        var (fresh, _) = state.BeginLease("laptop");
        var deks = vault.SealTo(fresh);
        using var forged = ApprovalKey.Derive(new byte[32], fresh.LeaseId);
        Assert.That(state.Seal(fresh.LeaseId, deks, ApprovalKey.Public(forged)).Result!.Accepted, Is.Empty);
    }
}
