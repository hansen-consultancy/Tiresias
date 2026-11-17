using NSec.Cryptography;

namespace Tiresias.Crypto;

/// <summary>
/// Anonymous public-key encryption: anyone holding the recipient's X25519 public key can seal,
/// only the private key opens. Used for the recovery wrap of a DEK and for sealing a lease's DEKs
/// to the broker's ephemeral lease key.
/// </summary>
/// <remarks>
/// Layout: ephemeral public key (32) ‖ nonce (24) ‖ XChaCha20-Poly1305 ciphertext.
/// The AEAD key is HKDF-SHA256 over the X25519 shared secret, salted with both public keys and bound
/// to <c>context</c>. A box opens only under the same context, so a box sealed for one purpose
/// (one secret, one lease) can't be replayed as another.
/// </remarks>
public static class SealedBox
{
    static readonly KeyAgreementAlgorithm Agreement = KeyAgreementAlgorithm.X25519;
    static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;

    const int PublicKeySize = 32;

    public static byte[] Seal(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> plaintext, string context)
    {
        var recipient = PublicKey.Import(Agreement, recipientPublicKey, KeyBlobFormat.RawPublicKey);
        using var ephemeral = Key.Create(Agreement);
        var ephemeralPublic = ephemeral.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        using var aeadKey = DeriveKey(ephemeral, recipient, ephemeralPublic, recipientPublicKey, context)
            ?? throw new CryptographicFailureException("Recipient public key is unusable (low order).");
        var nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(Aead.NonceSize);
        var ciphertext = Aead.Encrypt(aeadKey, nonce, Context(context), plaintext);

        return [.. ephemeralPublic, .. nonce, .. ciphertext];
    }

    /// <returns>The plaintext, or <c>null</c> when the box was tampered with, sealed to another key or sealed under another context.</returns>
    public static byte[]? Open(Key recipient, ReadOnlySpan<byte> box, string context)
    {
        if (box.Length < PublicKeySize + Aead.NonceSize + Aead.TagSize)
            return null;

        var ephemeralPublicBytes = box[..PublicKeySize];
        if (!PublicKey.TryImport(Agreement, ephemeralPublicBytes, KeyBlobFormat.RawPublicKey, out var ephemeralPublic) || ephemeralPublic is null)
            return null;

        var recipientPublic = recipient.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        using var aeadKey = DeriveKey(recipient, ephemeralPublic, ephemeralPublicBytes, recipientPublic, context);
        if (aeadKey is null)
            return null;

        var nonce = box.Slice(PublicKeySize, Aead.NonceSize);
        var ciphertext = box[(PublicKeySize + Aead.NonceSize)..];
        var plaintext = new byte[ciphertext.Length - Aead.TagSize];
        return Aead.Decrypt(aeadKey, nonce, Context(context), ciphertext, plaintext) ? plaintext : null;
    }

    /// <returns><c>null</c> for a low-order public key, which yields no usable shared secret.</returns>
    static Key? DeriveKey(Key own, PublicKey other, ReadOnlySpan<byte> ephemeralPublic, ReadOnlySpan<byte> recipientPublic, string context)
    {
        using var shared = Agreement.Agree(own, other);
        if (shared is null)
            return null;
        byte[] salt = [.. ephemeralPublic, .. recipientPublic];
        return KeyDerivationAlgorithm.HkdfSha256.DeriveKey(shared, salt, Context(context), Aead);
    }

    static byte[] Context(string context) => System.Text.Encoding.UTF8.GetBytes("tiresias/v1/" + context);
}

public sealed class CryptographicFailureException(string message) : Exception(message);
