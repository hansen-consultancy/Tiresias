using System.Text;
using NSec.Cryptography;

namespace Tiresias.Transport;

/// <summary>
/// What <c>POST /lease/begin</c> returns: a fresh X25519 lease key, signed by the broker's long-term
/// Ed25519 identity. The Keyring checks the signature against the identity it pinned at enrolment
/// before sealing any DEK to the key, so a man in the middle can't offer its own.
/// </summary>
/// <param name="HardCapAt">Signed at whole-second precision, which is what travels on the wire.</param>
public sealed record LeaseOffer(string LeaseId, byte[] LeaseKey, DateTimeOffset HardCapAt)
{
    public byte[] Sign(Key identity) => SignatureAlgorithm.Ed25519.Sign(identity, SignedBytes());

    public bool Verify(PublicKey identity, ReadOnlySpan<byte> signature) =>
        SignatureAlgorithm.Ed25519.Verify(identity, SignedBytes(), signature);

    /// <summary>
    /// <see cref="Crypto.SealedBox"/> context a DEK is sealed under for this lease, so a sealed DEK
    /// opens only for this lease and only as this secret.
    /// </summary>
    public static string DekContext(string leaseId, string secretSlug) => $"lease\n{leaseId}\n{secretSlug}";

    byte[] SignedBytes() =>
        Encoding.UTF8.GetBytes($"tiresias/v1/lease-offer\n{LeaseId}\n{Convert.ToBase64String(LeaseKey)}\n{HardCapAt.ToUnixTimeSeconds()}");
}
