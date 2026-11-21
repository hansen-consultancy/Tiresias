using System.Text.Json;
using NSec.Cryptography;
using Tiresias.Agent;
using Tiresias.Transport;

namespace Tiresias.Tests;

public class BrokerEnrollmentTests
{
    static readonly TenantConfig Solo = new("default", new Uri("http://127.0.0.1:7780"), "local-id", "vault.json", "genesis", true);
    static readonly BrokerEnrollment Installed = new("S-1-5-21-1-2-3-1001", Solo);
    string? journal;

    [TearDown]
    public void RemoveJournal()
    {
        if (journal is not null)
            File.Delete(journal);
    }

    [Test]
    public void Installation_keeps_the_complete_recipient_together()
    {
        var binding = BrokerEnrollment.Read(Installed.Write());
        Assert.That(binding, Is.EqualTo(Installed));
        Assert.That(binding.Require(Solo, null), Is.EqualTo(Solo));
        foreach (var other in new[] { Solo with { Url = new("https://example.com") }, Solo with { GenesisHash = null },
            Solo with { IdentityKey = "other-id" }, Solo with { VaultPath = "other.json" }, Solo with { Solo = false } })
            Assert.That(() => binding.Require(other, null), Throws.InvalidOperationException);
    }

    [Test]
    public void Additional_tenants_need_their_own_installed_enrollment()
    {
        var remote = new TenantConfig("team", new("https://example.com"), "team-id", "team.json");
        Assert.That(Installed.Require(remote, remote), Is.EqualTo(remote));
        Assert.That(() => Installed.Require(remote, null), Throws.InvalidOperationException);
        Assert.That(() => Installed.Require(remote with { IdentityKey = "replacement" }, remote), Throws.InvalidOperationException);
    }

    [TestCase(true)]
    [TestCase(false)]
    public void Enrollment_history_distinguishes_authorization_from_completion(bool completes)
    {
        journal = Path.GetTempFileName();
        void Apply() => BrokerEnrollment.Apply(journal, Installed.OwnerSid, "install", Solo, () =>
        {
            if (!completes)
                throw new IOException("The operation was interrupted.");
        });
        if (completes)
            Apply();
        else
            Assert.That(Apply, Throws.TypeOf<IOException>());
        var rows = File.ReadLines(journal).Select(line => JsonSerializer.Deserialize<JsonElement>(line)).ToArray();
        Assert.That(rows.Select(row => row.GetProperty("outcome").GetString()), Is.EqualTo(completes ? new[] { "authorized", "completed" } : ["authorized"]));
        Assert.That(rows.Select(row => row.GetProperty("id").GetGuid()).Distinct().Count(), Is.EqualTo(1));
        Assert.That(rows[0].GetProperty("recipient").GetString(), Has.Length.EqualTo(64));
        Assert.That(File.ReadAllText(journal), Does.Not.Contain(Solo.VaultPath));
    }

    [Test]
    public void The_saved_offer_can_be_used_only_with_its_original_signature_recipient_and_lifetime()
    {
        using var identity = Key.Create(SignatureAlgorithm.Ed25519);
        using var other = Key.Create(SignatureAlgorithm.Ed25519);
        var now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
        var offer = new LeaseOffer("today", new byte[32], now.AddHours(1));
        var lease = new OpenLease(offer.LeaseId, offer.HardCapAt, Convert.ToBase64String(offer.LeaseKey), Convert.ToBase64String(offer.Sign(identity)));
        var pin = Convert.ToBase64String(identity.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var restored = JsonSerializer.Deserialize<OpenLease>(JsonSerializer.Serialize(lease, JsonSerializerOptions.Web), JsonSerializerOptions.Web)!;
        Assert.That(restored.Verify(pin, now)?.LeaseKey, Is.EqualTo(offer.LeaseKey));
        Assert.That(restored.Verify(Convert.ToBase64String(other.PublicKey.Export(KeyBlobFormat.RawPublicKey)), now), Is.Null);
        Assert.That(restored.Verify(pin, offer.HardCapAt), Is.Null);
        foreach (var changed in new[] { restored with { Signature = null }, restored with { LeaseId = "tomorrow" },
            restored with { LeaseKey = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()) }, restored with { LeaseKey = "invalid" },
            restored with { HardCapAt = offer.HardCapAt.AddSeconds(1) }, restored with { HardCapAt = offer.HardCapAt.AddTicks(1) } })
            Assert.That(changed.Verify(pin, now), Is.Null);
    }
}
