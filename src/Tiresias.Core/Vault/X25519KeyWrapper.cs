using Tiresias.Crypto;
using NSec.Cryptography;

namespace Tiresias.Vault;

/// <summary>
/// Wraps DEKs to an X25519 public key. Wrapping needs only the public key, so the vault can add a
/// secret's recovery copy without the recovery key ever being online. Unwrapping needs the private key.
/// </summary>
public sealed class X25519KeyWrapper : IKeyWrapper
{
    readonly byte[] publicKey;
    readonly Key? privateKey;

    X25519KeyWrapper(string id, byte[] publicKey, Key? privateKey)
    {
        Id = id;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public string Id { get; }

    /// <summary>A wrapper that can only wrap, for when the private key is offline.</summary>
    public static X25519KeyWrapper ForPublicKey(string id, byte[] publicKey) => new(id, publicKey, null);

    public static X25519KeyWrapper ForKey(string id, Key key) =>
        new(id, key.PublicKey.Export(KeyBlobFormat.RawPublicKey), key);

    public byte[] Wrap(ReadOnlySpan<byte> dek, string context) => SealedBox.Seal(publicKey, dek, context);

    public byte[]? Unwrap(ReadOnlySpan<byte> wrapped, string context) =>
        privateKey is null ? null : SealedBox.Open(privateKey, wrapped, context);
}
