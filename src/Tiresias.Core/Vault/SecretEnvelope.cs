using NSec.Cryptography;

namespace Tiresias.Vault;

/// <summary>
/// Wraps and unwraps a secret's data-encryption key (DEK). One implementation per key that may open
/// the vault: the TPM key behind Windows Hello (day to day) and the offline recovery key.
/// </summary>
public interface IKeyWrapper
{
    /// <summary>Stable name the wrapped DEK is stored under, e.g. <c>tpm</c> or <c>recovery</c>.</summary>
    string Id { get; }

    byte[] Wrap(ReadOnlySpan<byte> dek, string context);

    /// <returns>The DEK, or <c>null</c> when this wrapper can't open it (wrong key, tampered, other context).</returns>
    byte[]? Unwrap(ReadOnlySpan<byte> wrapped, string context);
}

/// <summary>
/// One secret at rest: the value encrypted under its own DEK, and that DEK wrapped once per
/// <see cref="IKeyWrapper"/>. Holds no plaintext and no usable key.
/// </summary>
/// <param name="PolicyHash">
/// The <see cref="PolicyBinding.Hash"/> of the policy approved for this secret, or <c>null</c> for
/// an unbound one. It is part of the value's associated data, so changing or clearing it on disk
/// makes the value fail to open; <see cref="PolicyBinding.Allows"/> compares it with the policy
/// in force.
/// </param>
public sealed record SealedSecret(
    string Slug,
    int Version,
    IReadOnlyDictionary<string, byte[]> WrappedDeks,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[]? PolicyHash = null);

/// <summary>
/// Envelope encryption for vault secrets. The slug and version are bound into both the value's AAD
/// and the DEK wrap context, so neither a ciphertext nor a wrapped DEK can be moved onto another
/// secret, or rolled back to an older version, without failing to open. A secret sealed with a
/// policy hash carries it, bound the same way.
/// </summary>
public static class SecretEnvelope
{
    static readonly AeadAlgorithm Aead = AeadAlgorithm.XChaCha20Poly1305;

    public const int DekSize = 32;

    /// <param name="policyHash"><see cref="PolicyBinding.Hash"/> to bind a vault secret to its policy; <c>null</c> for an unbound secret.</param>
    public static SealedSecret Seal(string slug, int version, ReadOnlySpan<byte> value, IEnumerable<IKeyWrapper> wrappers, byte[]? policyHash = null)
    {
        var dek = System.Security.Cryptography.RandomNumberGenerator.GetBytes(DekSize);
        try
        {
            using var key = Key.Import(Aead, dek, KeyBlobFormat.RawSymmetricKey);
            var nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(Aead.NonceSize);
            var ciphertext = Aead.Encrypt(key, nonce, ValueContext(slug, version, policyHash), value);

            var context = DekContext(slug, version);
            var wrapped = wrappers.ToDictionary(w => w.Id, w => w.Wrap(dek, context));
            if (wrapped.Count == 0)
                throw new ArgumentException("A secret needs at least one key wrapper, or nothing can ever open it.", nameof(wrappers));

            return new(slug, version, wrapped, nonce, ciphertext, policyHash);
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    /// <returns>The DEK, or <c>null</c> when the secret has no DEK for this wrapper or it doesn't open.</returns>
    public static byte[]? UnwrapDek(SealedSecret secret, IKeyWrapper wrapper) =>
        secret.WrappedDeks.TryGetValue(wrapper.Id, out var wrapped)
            ? wrapper.Unwrap(wrapped, DekContext(secret.Slug, secret.Version))
            : null;

    /// <summary>Opens the value. Whether its policy is the one in force is <see cref="PolicyBinding.Allows"/>' question, not this one's.</summary>
    /// <returns>The value, or <c>null</c> when the DEK is wrong or the secret was tampered with.</returns>
    public static byte[]? Open(SealedSecret secret, ReadOnlySpan<byte> dek)
    {
        if (dek.Length != DekSize || secret.Ciphertext.Length < Aead.TagSize)
            return null;
        using var key = Key.Import(Aead, dek, KeyBlobFormat.RawSymmetricKey);
        var value = new byte[secret.Ciphertext.Length - Aead.TagSize];
        return Aead.Decrypt(key, secret.Nonce, ValueContext(secret.Slug, secret.Version, secret.PolicyHash), secret.Ciphertext, value) ? value : null;
    }

    /// <summary>
    /// Approves a new policy for a secret: the same value as the next version, bound to
    /// <paramref name="policyHash"/>, under the same DEK. A broker holding that DEK keeps serving it.
    /// </summary>
    /// <param name="wrappers">Every wrapper the DEK is kept for; the wrap context names the version, so each wraps again.</param>
    /// <returns>The rebound secret, or <c>null</c> when <paramref name="dek"/> doesn't open it.</returns>
    public static SealedSecret? Rebind(SealedSecret secret, ReadOnlySpan<byte> dek, byte[] policyHash, IEnumerable<IKeyWrapper> wrappers)
    {
        if (Open(secret, dek) is not { } value)
            return null;
        try
        {
            using var key = Key.Import(Aead, dek, KeyBlobFormat.RawSymmetricKey);
            var version = secret.Version + 1;
            var nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(Aead.NonceSize);
            var ciphertext = Aead.Encrypt(key, nonce, ValueContext(secret.Slug, version, policyHash), value);
            var context = DekContext(secret.Slug, version);
            var wrapped = new Dictionary<string, byte[]>();
            foreach (var wrapper in wrappers)
                wrapped[wrapper.Id] = wrapper.Wrap(dek, context);
            if (wrapped.Count == 0)
                throw new ArgumentException("A secret needs at least one key wrapper, or nothing can ever open it.", nameof(wrappers));
            return new(secret.Slug, version, wrapped, nonce, ciphertext, policyHash);
        }
        finally
        {
            Array.Clear(value);
        }
    }

    /// <summary>Adds (or replaces) one wrapper's copy of the DEK, e.g. re-wrapping to a new TPM key from the recovery key.</summary>
    public static SealedSecret Rewrap(SealedSecret secret, ReadOnlySpan<byte> dek, IKeyWrapper wrapper)
    {
        var wrapped = new Dictionary<string, byte[]>(secret.WrappedDeks)
        {
            [wrapper.Id] = wrapper.Wrap(dek, DekContext(secret.Slug, secret.Version)),
        };
        return secret with { WrappedDeks = wrapped };
    }

    internal static string DekContext(string slug, int version) => $"dek\n{slug}\n{version}";

    static byte[] ValueContext(string slug, int version, byte[]? policyHash) => System.Text.Encoding.UTF8.GetBytes(policyHash is null
        ? $"tiresias/v1/value\n{slug}\n{version}"
        : $"tiresias/v2/value\n{slug}\n{version}\n{Convert.ToHexStringLower(policyHash)}");
}
