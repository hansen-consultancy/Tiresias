using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Tiresias.Vault;

/// <summary>
/// Wraps DEKs under a key derived from a signature over a fixed challenge, for signing keys that
/// can't be exported or used for encryption directly (a Windows Hello key in the TPM). The wrap key
/// is HKDF-SHA256 of the signature; a wrap is nonce (24) ‖ XChaCha20-Poly1305 ciphertext, with the
/// context as AAD.
/// </summary>
/// <remarks>
/// Correct only for a <b>deterministic</b> signer (RSA PKCS#1 v1.5, Ed25519): the same key must
/// produce the same signature over <see cref="Challenge"/> every time, or nothing wrapped earlier
/// opens again. A non-deterministic signer (ECDSA, RSA-PSS) makes every unwrap return <c>null</c>.
/// The signer runs once per instance, on first use, and the derived key is kept until
/// <see cref="Dispose"/>, so one instance costs one user gesture however many DEKs it handles.
/// </remarks>
public sealed class SignatureDerivedWrapper(string id, Func<byte[], byte[]> sign) : IKeyWrapper, IDisposable
{
    public static readonly byte[] Challenge = "tiresias/v1/wrap"u8.ToArray();

    static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;
    static readonly byte[] Info = "tiresias/v1/signature-wrap-key"u8.ToArray();
    static readonly byte[] ApprovalInfo = "tiresias/v1/approval-root"u8.ToArray();

    Key? key;
    byte[]? approvalRoot;

    public string Id { get; } = id;

    public byte[] Wrap(ReadOnlySpan<byte> dek, string context)
    {
        var nonce = RandomNumberGenerator.GetBytes(Aead.NonceSize);
        return [.. nonce, .. Aead.Encrypt(DerivedKey(), nonce, Aad(context), dek)];
    }

    public byte[]? Unwrap(ReadOnlySpan<byte> wrapped, string context)
    {
        if (wrapped.Length < Aead.NonceSize + Aead.TagSize)
            return null;
        var dek = new byte[wrapped.Length - Aead.NonceSize - Aead.TagSize];
        return Aead.Decrypt(DerivedKey(), wrapped[..Aead.NonceSize], Aad(context), wrapped[Aead.NonceSize..], dek) ? dek : null;
    }

    /// <summary>
    /// The lease's approval key (<see cref="Access.ApprovalKey"/>), from the same signature as the wrap
    /// key: no extra gesture when the wrap key is already derived, one when it isn't.
    /// </summary>
    public Key ApprovalKey(string leaseId)
    {
        DerivedKey();
        return Access.ApprovalKey.Derive(approvalRoot!, leaseId);
    }

    /// <summary>The service enrolls the public half once and verifies subsequent vault revisions with it.</summary>
    public Key RevisionKey()
    {
        DerivedKey();
        Span<byte> seed = stackalloc byte[32];
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, approvalRoot!, seed, salt: [], info: "tiresias/v1/vault-revision-key"u8);
            return Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public void Dispose()
    {
        key?.Dispose();
        key = null;
        if (approvalRoot is not null)
            Array.Clear(approvalRoot);
        approvalRoot = null;
    }

    Key DerivedKey()
    {
        if (key is not null)
            return key;
        var signature = sign(Challenge);
        var raw = HKDF.DeriveKey(HashAlgorithmName.SHA256, signature, Aead.KeySize, salt: [], info: Info);
        try
        {
            approvalRoot = HKDF.DeriveKey(HashAlgorithmName.SHA256, signature, 32, salt: [], info: ApprovalInfo);
            return key = Key.Import(Aead, raw, KeyBlobFormat.RawSymmetricKey);
        }
        finally
        {
            Array.Clear(raw);
            Array.Clear(signature);
        }
    }

    static byte[] Aad(string context) => Encoding.UTF8.GetBytes("tiresias/v1/signature-wrap\n" + context);
}
