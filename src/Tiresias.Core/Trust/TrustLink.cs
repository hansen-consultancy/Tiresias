using NSec.Cryptography;

namespace Tiresias.Trust;

/// <summary>
/// A key a link introduces. Ids are unique for the chain's lifetime: a revoked id is never reused,
/// so a revocation can't be undone by re-adding the same id.
/// </summary>
/// <param name="PublicKey">Raw Ed25519 public key.</param>
/// <param name="Paper">An offline paper key: signs links only, and every signature it adds to a link is a break-glass use.</param>
/// <param name="Hello">The device's Windows Hello key (RSA SubjectPublicKeyInfo), which signs links that add trust. Absent for a paper key.</param>
public sealed record DeviceRef(string Id, byte[] PublicKey, bool Paper = false, byte[]? Hello = null);

/// <param name="AdminThreshold">How many distinct admin users must sign an admin link (add-user, remove-user, add-broker, set-policy).</param>
public sealed record TrustPolicy(int AdminThreshold = 1);

/// <summary>What a link does. Every key a body introduces must countersign its link.</summary>
public abstract record LinkBody;

public sealed record Genesis(string Tenant, string Admin, DeviceRef Device, DeviceRef PaperKey, TrustPolicy Policy) : LinkBody;

/// <summary>A user arrives with their first device (and optionally a paper key), or nobody could ever sign an add-device for them.</summary>
public sealed record AddUser(string User, bool Admin, DeviceRef Device, DeviceRef? PaperKey = null) : LinkBody;

public sealed record AddDevice(string User, DeviceRef Device) : LinkBody;

public sealed record RevokeDevice(string DeviceId) : LinkBody;

/// <summary>Removes the user and retires all their devices.</summary>
public sealed record RemoveUser(string User) : LinkBody;

public sealed record AddBroker(string Broker, byte[] PublicKey) : LinkBody;

public sealed record SetPolicy(TrustPolicy Policy) : LinkBody;

/// <summary>
/// Names the Hello key of a device enrolled before links needed one. Signed by that device with both
/// keys and by a paper key of its user, once.
/// </summary>
/// <param name="Hello">RSA SubjectPublicKeyInfo.</param>
public sealed record BindHello(string DeviceId, byte[] Hello) : LinkBody;

/// <param name="Hello">The signer's Hello signature over <see cref="TrustChain.PresenceBytes"/>, proving a person was there.</param>
public sealed record LinkSignature(string DeviceId, byte[] Signature, byte[]? Hello = null);

/// <summary>
/// One link of a tenant's append-only trust chain. All signatures cover the same bytes,
/// <see cref="TrustChain.SignedBytes"/>; whether a signature authorizes the link or countersigns a
/// key it introduces is decided by the verifier, not recorded here.
/// </summary>
/// <param name="Prev"><see cref="TrustChain.Hash"/> of the previous link; <see cref="TrustChain.ZeroHash"/> for genesis.</param>
/// <param name="Time">Whole seconds; the canonical form carries Unix seconds.</param>
public sealed record TrustLink(long Seq, string Prev, DateTimeOffset Time, LinkBody Body, IReadOnlyList<LinkSignature> Signatures);

/// <summary>A device's Windows Hello key, for signing links. Each signature shows a Hello prompt.</summary>
/// <param name="PublicKey">RSA SubjectPublicKeyInfo.</param>
/// <param name="Sign">RSA PKCS#1 v1.5 SHA-256 signature over the given bytes.</param>
public sealed record HelloKey(byte[] PublicKey, Func<byte[], byte[]> Sign);

/// <summary>A device's private key, and its Hello key when it has one, for building links.</summary>
public sealed record Signer(string DeviceId, Key Key, HelloKey? Hello = null)
{
    public DeviceRef Describe(bool paper = false) => new(DeviceId, Key.PublicKey.Export(KeyBlobFormat.RawPublicKey), paper, Hello?.PublicKey);
}
