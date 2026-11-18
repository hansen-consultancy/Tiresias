using System.Text.Json.Nodes;
using NSec.Cryptography;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Tests;

/// <summary>Restoring from the recovery key: the old PC's Hello key is gone, a new one takes its place.</summary>
public class RecoveryRewrapTests
{
    const string Id = "6b8e0c4e-test";

    // All three wrap under the ids the app uses: a new PC's Hello credential has the same id as the old one's.
    static X25519KeyWrapper NewKey(string id) => X25519KeyWrapper.ForKey(id, Key.Create(KeyAgreementAlgorithm.X25519));

    readonly X25519KeyWrapper oldHello = NewKey("hello");
    readonly X25519KeyWrapper newHello = NewKey("hello");
    readonly X25519KeyWrapper recovery = NewKey("recovery");

    static string Value(SealedSecret secret, IKeyWrapper wrapper) =>
        System.Text.Encoding.UTF8.GetString(SecretEnvelope.Open(secret, SecretEnvelope.UnwrapDek(secret, wrapper)!)!);

    [Test]
    public void A_secret_from_the_old_Hello_key_opens_with_the_new_one_afterwards()
    {
        var secret = SecretEnvelope.Seal("llm", 3, "Bearer sk"u8, [oldHello, recovery]);

        var (outcome, result, recoveryOpens) = RecoveryRewrap.Secret(secret, newHello, recovery);

        Assert.That(outcome, Is.EqualTo(RewrapOutcome.Rewrapped));
        Assert.That(recoveryOpens, Is.True);
        Assert.That(Value(result, newHello), Is.EqualTo("Bearer sk"));
        Assert.That(Value(result, recovery), Is.EqualTo("Bearer sk"), "the recovery copy stays");
        Assert.That(result.Version, Is.EqualTo(3));
        Assert.That(result.Ciphertext, Is.EqualTo(secret.Ciphertext), "nothing is re-encrypted");
    }

    [Test]
    public void A_secret_this_Hello_key_opens_is_left_as_it_is()
    {
        var secret = SecretEnvelope.Seal("llm", 1, "v"u8, [newHello, recovery]);

        var (outcome, result, recoveryOpens) = RecoveryRewrap.Secret(secret, newHello, recovery);

        Assert.That(outcome, Is.EqualTo(RewrapOutcome.AlreadyOpens));
        Assert.That(result, Is.SameAs(secret));
        Assert.That(recoveryOpens, Is.True);
    }

    [Test]
    public void Another_recovery_key_opens_nothing_and_changes_nothing()
    {
        var secret = SecretEnvelope.Seal("llm", 1, "v"u8, [oldHello, recovery]);

        var (outcome, result, recoveryOpens) = RecoveryRewrap.Secret(secret, newHello, NewKey("recovery"));

        Assert.That(outcome, Is.EqualTo(RewrapOutcome.DoesNotOpen));
        Assert.That(result, Is.SameAs(secret));
        Assert.That(recoveryOpens, Is.False);
    }

    [Test]
    public void A_sealed_secrets_file_keeps_its_version_and_the_plain_keys_beside_it()
    {
        var document = new JsonObject { ["ConnectionStrings"] = new JsonObject { ["Default"] = "Server=db;Password=hunter2" } };
        var sealedText = UserSecretsVault.Seal(Id, 4, document, [oldHello, recovery]);
        var withAddition = JsonNode.Parse(sealedText)!.AsObject();
        withAddition["Added:Later"] = "plain";

        var (outcome, text, _) = UserSecretsVault.Rewrap(Id, withAddition.ToJsonString(), newHello, recovery);
        var load = UserSecretsVault.Open(Id, text, newHello);

        Assert.That(outcome, Is.EqualTo(RewrapOutcome.Rewrapped));
        Assert.That(load.Version, Is.EqualTo(4));
        Assert.That(load.Keys, Is.EquivalentTo(new[] { "ConnectionStrings:Default", "Added:Later" }));
        Assert.That(load.PlaintextKeys, Is.EqualTo(new[] { "Added:Later" }), "still to be sealed by the agent, as before");
        Assert.That(text, Does.Not.Contain("hunter2"));
    }

    [Test]
    public void A_file_that_needs_nothing_comes_back_unchanged()
    {
        var sealedText = UserSecretsVault.Seal(Id, 1, new JsonObject { ["A"] = "b" }, [newHello, recovery]);

        var (outcome, text, _) = UserSecretsVault.Rewrap(Id, sealedText, newHello, recovery);

        Assert.That(outcome, Is.EqualTo(RewrapOutcome.AlreadyOpens));
        Assert.That(text, Is.EqualTo(sealedText));
    }

    [Test]
    public void Opens_tells_which_Hello_key_a_file_is_sealed_to_without_reading_it()
    {
        var sealedText = UserSecretsVault.Seal(Id, 1, new JsonObject { ["A"] = "b" }, [oldHello, recovery]);

        Assert.That(UserSecretsVault.Opens(Id, sealedText, oldHello), Is.True);
        Assert.That(UserSecretsVault.Opens(Id, sealedText, newHello), Is.False);
        Assert.That(UserSecretsVault.Opens("another-id", sealedText, oldHello), Is.False, "the id is bound into the seal");
        Assert.That(UserSecretsVault.Opens(Id, """{ "A": "b" }""", oldHello), Is.False, "a plain file isn't sealed");
    }

    [TestCase(false, false, 0, 0, true, TestName = "A new PC with nothing sealed takes the typed key")]
    [TestCase(false, false, 3, 3, true, TestName = "A new PC takes the key that opened its copied secrets")]
    [TestCase(false, false, 3, 1, true, TestName = "A new PC takes the key that opened some of them")]
    [TestCase(true, true, 3, 3, false, TestName = "The key this device stored stays")]
    [TestCase(true, false, 3, 3, true, TestName = "A newer key nothing needs is replaced by the one that opens everything")]
    [TestCase(true, false, 3, 2, false, TestName = "A stored key some secrets still need is kept")]
    [TestCase(true, false, 0, 0, false, TestName = "With nothing sealed a stored key is not replaced")]
    public void Adopting_the_typed_key(bool hasStoredKey, bool storedMatches, int items, int recoveryOpens, bool adopt) =>
        Assert.That(RecoveryRewrap.ShouldAdopt(hasStoredKey, storedMatches, items, recoveryOpens), Is.EqualTo(adopt));
}
