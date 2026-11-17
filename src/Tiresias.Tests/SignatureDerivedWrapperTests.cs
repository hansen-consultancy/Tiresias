using System.Security.Cryptography;
using Tiresias.Vault;

namespace Tiresias.Tests;

/// <summary>The Hello wrap scheme, with an HMAC standing in for the TPM's deterministic RSA signature.</summary>
public class SignatureDerivedWrapperTests
{
    static readonly byte[] Dek = RandomNumberGenerator.GetBytes(SecretEnvelope.DekSize);
    static readonly byte[] SignerKey = RandomNumberGenerator.GetBytes(32);

    static Func<byte[], byte[]> Deterministic(byte[] key) => data => HMACSHA256.HashData(key, data);

    [Test]
    public void A_wrap_opens_in_a_later_instance_with_the_same_signer()
    {
        byte[] wrapped;
        using (var first = new SignatureDerivedWrapper("hello", Deterministic(SignerKey)))
            wrapped = first.Wrap(Dek, "dek\nllm\n1");
        using var second = new SignatureDerivedWrapper("hello", Deterministic(SignerKey));
        Assert.That(second.Unwrap(wrapped, "dek\nllm\n1"), Is.EqualTo(Dek));
    }

    [Test]
    public void A_non_deterministic_signer_fails_to_unwrap_with_null_not_an_exception()
    {
        Func<byte[], byte[]> randomised = _ => RandomNumberGenerator.GetBytes(256);
        byte[] wrapped;
        using (var first = new SignatureDerivedWrapper("hello", randomised))
            wrapped = first.Wrap(Dek, "c");
        using var second = new SignatureDerivedWrapper("hello", randomised);
        Assert.That(second.Unwrap(wrapped, "c"), Is.Null);
    }

    [Test]
    public void Another_signing_key_does_not_unwrap()
    {
        using var wrapper = new SignatureDerivedWrapper("hello", Deterministic(SignerKey));
        using var other = new SignatureDerivedWrapper("hello", Deterministic(RandomNumberGenerator.GetBytes(32)));
        Assert.That(other.Unwrap(wrapper.Wrap(Dek, "c"), "c"), Is.Null);
    }

    [Test]
    public void Another_context_does_not_unwrap()
    {
        using var wrapper = new SignatureDerivedWrapper("hello", Deterministic(SignerKey));
        Assert.That(wrapper.Unwrap(wrapper.Wrap(Dek, "dek\nllm\n1"), "dek\nllm\n2"), Is.Null);
    }

    [Test]
    public void A_flipped_byte_or_a_truncated_wrap_does_not_unwrap()
    {
        using var wrapper = new SignatureDerivedWrapper("hello", Deterministic(SignerKey));
        var wrapped = wrapper.Wrap(Dek, "c");
        for (var i = 0; i < wrapped.Length; i++)
        {
            var tampered = (byte[])wrapped.Clone();
            tampered[i] ^= 1;
            Assert.That(wrapper.Unwrap(tampered, "c"), Is.Null, $"byte {i}");
        }
        Assert.That(wrapper.Unwrap(wrapped[..10], "c"), Is.Null);
    }

    [Test]
    public void One_instance_asks_the_signer_once_and_only_for_the_fixed_challenge()
    {
        var calls = new List<byte[]>();
        using var wrapper = new SignatureDerivedWrapper("hello", data =>
        {
            calls.Add(data);
            return HMACSHA256.HashData(SignerKey, data);
        });
        var a = wrapper.Wrap(Dek, "a");
        var b = wrapper.Wrap(Dek, "b");
        Assert.That(wrapper.Unwrap(a, "a"), Is.EqualTo(Dek));
        Assert.That(wrapper.Unwrap(b, "b"), Is.EqualTo(Dek));
        Assert.That(calls, Has.Count.EqualTo(1));
        Assert.That(calls[0], Is.EqualTo(SignatureDerivedWrapper.Challenge));
    }

    [Test]
    public void Works_as_a_vault_wrapper()
    {
        using var hello = new SignatureDerivedWrapper("hello", Deterministic(SignerKey));
        var secret = SecretEnvelope.Seal("llm-read", 1, "Bearer sk"u8, [hello]);
        using var later = new SignatureDerivedWrapper("hello", Deterministic(SignerKey));
        var dek = SecretEnvelope.UnwrapDek(secret, later)!;
        Assert.That(SecretEnvelope.Open(secret, dek), Is.EqualTo("Bearer sk"u8.ToArray()));
    }
}
