using Tiresias.Transport;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class RequestSignatureTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);
    static readonly long Ts = Now.ToUnixTimeSeconds();
    static readonly byte[] Body = """{"leaseId":"abc"}"""u8.ToArray();

    static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519);

    [Test]
    public void Verifies_what_was_signed()
    {
        using var key = NewKey();
        var sig = RequestSignature.Sign(key, "POST", "/lease/seal", Ts, Body);
        Assert.That(RequestSignature.Verify(key.PublicKey, "POST", "/lease/seal", Ts, Body, sig, Now), Is.True);
    }

    [Test]
    public void Is_bound_to_the_endpoint()
    {
        using var key = NewKey();
        var sig = RequestSignature.Sign(key, "POST", "/lease/end", Ts, Body);
        Assert.That(RequestSignature.Verify(key.PublicKey, "POST", "/lease/begin", Ts, Body, sig, Now), Is.False);
    }

    [Test]
    public void Is_bound_to_the_method()
    {
        using var key = NewKey();
        var sig = RequestSignature.Sign(key, "POST", "/lease/end", Ts, Body);
        Assert.That(RequestSignature.Verify(key.PublicKey, "PUT", "/lease/end", Ts, Body, sig, Now), Is.False);
    }

    [Test]
    public void A_tampered_body_fails()
    {
        using var key = NewKey();
        var sig = RequestSignature.Sign(key, "POST", "/lease/seal", Ts, Body);
        Assert.That(RequestSignature.Verify(key.PublicKey, "POST", "/lease/seal", Ts, """{"leaseId":"abd"}"""u8, sig, Now), Is.False);
    }

    [Test]
    public void Another_device_key_fails()
    {
        using var key = NewKey();
        using var other = NewKey();
        var sig = RequestSignature.Sign(key, "POST", "/lease/seal", Ts, Body);
        Assert.That(RequestSignature.Verify(other.PublicKey, "POST", "/lease/seal", Ts, Body, sig, Now), Is.False);
    }

    [TestCase(-301, false, TestName = "Older than 5 min fails")]
    [TestCase(-300, true, TestName = "Exactly 5 min old passes")]
    [TestCase(120, true, TestName = "2 min ahead passes")]
    [TestCase(121, false, TestName = "More than 2 min ahead fails")]
    public void Timestamp_window(int offsetSeconds, bool valid)
    {
        using var key = NewKey();
        var ts = Ts + offsetSeconds;
        var sig = RequestSignature.Sign(key, "POST", "/lease/seal", ts, Body);
        Assert.That(RequestSignature.Verify(key.PublicKey, "POST", "/lease/seal", ts, Body, sig, Now), Is.EqualTo(valid));
    }
}

public class LeaseOfferTests
{
    [Test]
    public void Verifies_under_the_broker_identity_only()
    {
        using var identity = Key.Create(SignatureAlgorithm.Ed25519);
        using var impostor = Key.Create(SignatureAlgorithm.Ed25519);
        var offer = new LeaseOffer("L1", new byte[32], DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
        var sig = offer.Sign(identity);

        Assert.That(offer.Verify(identity.PublicKey, sig), Is.True);
        Assert.That(offer.Verify(impostor.PublicKey, sig), Is.False);
    }

    [Test]
    public void A_swapped_lease_key_fails()
    {
        using var identity = Key.Create(SignatureAlgorithm.Ed25519);
        var offer = new LeaseOffer("L1", new byte[32], DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
        var sig = offer.Sign(identity);
        var swapped = offer with { LeaseKey = Enumerable.Repeat((byte)1, 32).ToArray() };
        Assert.That(swapped.Verify(identity.PublicKey, sig), Is.False);
    }
}
