using System.Text;
using Tiresias.Crypto;
using Tiresias.Vault;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class SealedBoxTests
{
    static Key NewKey() => Key.Create(KeyAgreementAlgorithm.X25519);
    static byte[] Pub(Key k) => k.PublicKey.Export(KeyBlobFormat.RawPublicKey);

    [Test]
    public void Round_trips_under_the_same_context()
    {
        using var key = NewKey();
        var box = SealedBox.Seal(Pub(key), "hello"u8, "lease\n1");
        Assert.That(SealedBox.Open(key, box, "lease\n1"), Is.EqualTo("hello"u8.ToArray()));
    }

    [Test]
    public void Does_not_open_under_another_context()
    {
        using var key = NewKey();
        var box = SealedBox.Seal(Pub(key), "hello"u8, "lease\n1");
        Assert.That(SealedBox.Open(key, box, "lease\n2"), Is.Null);
    }

    [Test]
    public void Does_not_open_with_another_key()
    {
        using var key = NewKey();
        using var other = NewKey();
        var box = SealedBox.Seal(Pub(key), "hello"u8, "c");
        Assert.That(SealedBox.Open(other, box, "c"), Is.Null);
    }

    [Test]
    public void Does_not_open_when_any_byte_is_flipped()
    {
        using var key = NewKey();
        var box = SealedBox.Seal(Pub(key), "hello"u8, "c");
        for (var i = 0; i < box.Length; i++)
        {
            var tampered = (byte[])box.Clone();
            tampered[i] ^= 1;
            Assert.That(SealedBox.Open(key, tampered, "c"), Is.Null, $"byte {i}");
        }
    }

    [Test]
    public void Rejects_a_truncated_box() =>
        Assert.That(SealedBox.Open(NewKey(), new byte[10], "c"), Is.Null);
}

public class SecretEnvelopeTests
{
    static X25519KeyWrapper Wrapper(string id, out Key key)
    {
        key = Key.Create(KeyAgreementAlgorithm.X25519);
        return X25519KeyWrapper.ForKey(id, key);
    }

    [Test]
    public void Each_wrapper_independently_opens_the_secret()
    {
        var tpm = Wrapper("tpm", out _);
        var recovery = Wrapper("recovery", out _);
        var sealedSecret = SecretEnvelope.Seal("llm-read", 1, "token-value"u8, [tpm, recovery]);

        foreach (var wrapper in new[] { tpm, recovery })
        {
            var dek = SecretEnvelope.UnwrapDek(sealedSecret, wrapper);
            Assert.That(dek, Is.Not.Null, wrapper.Id);
            Assert.That(SecretEnvelope.Open(sealedSecret, dek!), Is.EqualTo("token-value"u8.ToArray()));
        }
    }

    [Test]
    public void Holds_no_plaintext()
    {
        var value = Encoding.UTF8.GetBytes("super-secret-token-123");
        var sealedSecret = SecretEnvelope.Seal("s", 1, value, [Wrapper("tpm", out _)]);
        var all = sealedSecret.Ciphertext.Concat(sealedSecret.Nonce).Concat(sealedSecret.WrappedDeks.Values.SelectMany(v => v)).ToArray();
        Assert.That(Encoding.UTF8.GetString(all), Does.Not.Contain("super-secret"));
    }

    [Test]
    public void A_public_key_only_wrapper_wraps_but_cannot_unwrap()
    {
        var full = Wrapper("recovery", out var key);
        var publicOnly = X25519KeyWrapper.ForPublicKey("recovery", key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var sealedSecret = SecretEnvelope.Seal("s", 1, "v"u8, [publicOnly]);

        Assert.That(SecretEnvelope.UnwrapDek(sealedSecret, publicOnly), Is.Null);
        Assert.That(SecretEnvelope.UnwrapDek(sealedSecret, full), Is.Not.Null);
    }

    [Test]
    public void Ciphertext_moved_onto_another_slug_does_not_open()
    {
        var tpm = Wrapper("tpm", out _);
        var original = SecretEnvelope.Seal("llm-read", 1, "v"u8, [tpm]);
        var dek = SecretEnvelope.UnwrapDek(original, tpm)!;

        Assert.That(SecretEnvelope.Open(original with { Slug = "llm-admin" }, dek), Is.Null);
    }

    [Test]
    public void Wrapped_dek_moved_onto_another_version_does_not_unwrap()
    {
        var tpm = Wrapper("tpm", out _);
        var v1 = SecretEnvelope.Seal("s", 1, "old"u8, [tpm]);
        Assert.That(SecretEnvelope.UnwrapDek(v1 with { Version = 2 }, tpm), Is.Null);
    }

    [Test]
    public void Rewrap_adds_a_new_wrapper_from_a_recovered_dek()
    {
        var recovery = Wrapper("recovery", out _);
        var newTpm = Wrapper("tpm", out _);
        var sealedSecret = SecretEnvelope.Seal("s", 1, "v"u8, [recovery]);
        var dek = SecretEnvelope.UnwrapDek(sealedSecret, recovery)!;

        var rewrapped = SecretEnvelope.Rewrap(sealedSecret, dek, newTpm);

        Assert.That(SecretEnvelope.Open(rewrapped, SecretEnvelope.UnwrapDek(rewrapped, newTpm)!), Is.EqualTo("v"u8.ToArray()));
        Assert.That(rewrapped.WrappedDeks.Keys, Is.EquivalentTo(new[] { "recovery", "tpm" }));
    }

    [Test]
    public void Refuses_to_seal_with_no_wrapper() =>
        Assert.Throws<ArgumentException>(() => SecretEnvelope.Seal("s", 1, "v"u8, []));
}
