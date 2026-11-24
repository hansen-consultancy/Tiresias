using System.Security.Cryptography;
using NSec.Cryptography;

namespace Tiresias.Trust;

public enum TrustFailureKind
{
    BadSignature,
    BadPrev,
    BadSeq,
    UnauthorizedSigner,
    MissingCountersignature,
    InsufficientAdminSignatures,
    GenesisMismatch,
    /// <summary>The chain is shorter than the head this verifier already accepted.</summary>
    Rollback,
    /// <summary>The chain differs from the accepted head at a seq already seen.</summary>
    Fork,
    RevokedSigner,
    /// <summary>Signatures are fine but the link makes no sense: unknown user, reused id, impossible threshold.</summary>
    InvalidLink,
    /// <summary>A link that adds trust lacks a Hello signature from a device that signed it or that it adds.</summary>
    PresenceRequired,
}

public sealed record TrustFailure(TrustFailureKind Kind, long Seq, string Detail);

public sealed record ChainHead(long Seq, string Hash);

public sealed record TrustedUser(string Name, bool Admin);

/// <param name="Hello">The device's Hello key (RSA SubjectPublicKeyInfo); <c>null</c> for a paper key or a device not bound yet.</param>
public sealed record TrustedDevice(string Id, string User, PublicKey Key, bool Paper, byte[]? Hello = null);

/// <summary>A paper key authorized a link. Callers must alert on every one.</summary>
public sealed record BreakGlassUse(long Seq, string DeviceId, string User);

/// <summary>What a verified chain proves, as of its head.</summary>
/// <param name="Devices">Active (unrevoked, user not removed) device keys by id, paper keys included and flagged.</param>
public sealed record TrustState(
    string Tenant,
    ChainHead Head,
    IReadOnlyDictionary<string, TrustedUser> Users,
    IReadOnlyDictionary<string, TrustedDevice> Devices,
    IReadOnlyDictionary<string, byte[]> Brokers,
    TrustPolicy Policy,
    IReadOnlyList<BreakGlassUse> BreakGlassUses)
{
    public IEnumerable<TrustedDevice> DevicesOf(string user) => Devices.Values.Where(d => d.User == user);
}

public sealed record TrustVerification(TrustState? State, TrustFailure? Failure)
{
    public bool IsValid => State is not null;
}

/// <summary>
/// Replays a chain from its pinned genesis and derives who holds which keys. Pure: trusts nothing
/// but the signatures and the two anchors the caller remembers (genesis hash, accepted head).
/// </summary>
/// <remarks>
/// Every signature on a link is either a countersignature by a key the link introduces (all of
/// which must sign) or an authorization by an active device, and every authorizer must be entitled
/// to sign that kind of link: add-device by the user's own devices; revoke-device by the target's
/// user or an admin; the admin links by admins, counting distinct admin users against the policy
/// threshold in force before the link. Any other signer fails the link.
/// <para>
/// Links that add trust (add-device, add-user, add-broker, set-policy, bind-hello) also need
/// presence (docs/trust-links.md): every device that signs them, and every device they add, signs
/// with its Hello key too, which the chain anchors from genesis on. Paper keys sign without one.
/// A genesis without a Hello key stays valid, for chains made before this rule, but its device
/// authorizes no such link until a bind-hello names its Hello key.
/// </para>
/// </remarks>
public static class TrustChainVerifier
{
    static readonly SignatureAlgorithm Ed25519 = SignatureAlgorithm.Ed25519;

    /// <summary>
    /// Whether the chain in <paramref name="chainJson"/> names <paramref name="deviceId"/>'s Windows
    /// Hello key; <c>null</c> when the bytes aren't a chain from that genesis or the device isn't in it.
    /// </summary>
    public static bool? HelloBound(ReadOnlySpan<byte> chainJson, string pinnedGenesisHash, string deviceId) =>
        TrustLinkJson.ParseChain(chainJson) is { } chain
        && Verify(chain, pinnedGenesisHash).State is { } state
        && state.Devices.TryGetValue(deviceId, out var device)
            ? device.Hello is not null
            : null;

    public static TrustVerification Verify(IReadOnlyList<TrustLink> links, string pinnedGenesisHash, ChainHead? previouslyAcceptedHead = null)
    {
        if (previouslyAcceptedHead is { } head)
        {
            if (links.Count <= head.Seq)
                return Fail(TrustFailureKind.Rollback, links.Count - 1, $"chain ends before accepted seq {head.Seq}");
            if (TrustChain.Hash(links[(int)head.Seq]) != head.Hash)
                return Fail(TrustFailureKind.Fork, head.Seq, "differs from the accepted head");
        }
        if (links.Count == 0 || TrustChain.Hash(links[0]) != pinnedGenesisHash)
            return Fail(TrustFailureKind.GenesisMismatch, 0, "genesis does not match the pinned hash");

        var replay = new Replay();
        var prev = TrustChain.ZeroHash;
        for (var i = 0; i < links.Count; i++)
        {
            var link = links[i];
            if (link.Seq != i)
                return Fail(TrustFailureKind.BadSeq, i, $"seq {link.Seq} at position {i}");
            if (link.Prev != prev)
                return Fail(TrustFailureKind.BadPrev, i, "prev is not the previous link's hash");
            if (replay.Apply(link) is { } failure)
                return new(null, failure);
            prev = TrustChain.Hash(link);
        }
        return new(replay.Snapshot(new(links.Count - 1, prev)), null);
    }

    static TrustVerification Fail(TrustFailureKind kind, long seq, string detail) => new(null, new(kind, seq, detail));

    sealed class Replay
    {
        string tenant = "";
        TrustPolicy policy = new();
        readonly Dictionary<string, TrustedUser> users = [];
        readonly Dictionary<string, TrustedDevice> devices = [];
        readonly HashSet<string> retired = [];
        readonly Dictionary<string, byte[]> brokers = [];
        readonly List<BreakGlassUse> breakGlass = [];

        public TrustState Snapshot(ChainHead head) =>
            new(tenant, head, users.ToDictionary(), devices.ToDictionary(), brokers.ToDictionary(), policy, breakGlass.ToArray());

        public TrustFailure? Apply(TrustLink link)
        {
            var seq = link.Seq;
            TrustFailure Failed(TrustFailureKind kind, string detail) => new(kind, seq, detail);

            if ((seq == 0) != (link.Body is Genesis))
                return Failed(TrustFailureKind.InvalidLink, "genesis must be the first link, and only the first");

            // Keys this link introduces.
            var introduced = new Dictionary<string, TrustedDevice>();
            var owner = link.Body switch { Genesis g => g.Admin, AddUser u => u.User, AddDevice d => d.User, _ => "" };
            DeviceRef?[] refs = link.Body switch
            {
                Genesis g => [g.Device, g.PaperKey],
                AddUser u => [u.Device, u.PaperKey],
                AddDevice d => [d.Device],
                _ => [],
            };
            foreach (var r in refs.OfType<DeviceRef>())
            {
                if (devices.ContainsKey(r.Id) || retired.Contains(r.Id) || introduced.ContainsKey(r.Id))
                    return Failed(TrustFailureKind.InvalidLink, $"device id '{r.Id}' already used");
                if (!PublicKey.TryImport(Ed25519, r.PublicKey, KeyBlobFormat.RawPublicKey, out var key))
                    return Failed(TrustFailureKind.InvalidLink, $"device '{r.Id}' has no valid Ed25519 key");
                if (r.Hello is not null && (r.Paper || !IsHelloKey(r.Hello)))
                    return Failed(TrustFailureKind.InvalidLink, $"device '{r.Id}' has an invalid Hello key");
                if (r is { Paper: false, Hello: null } && link.Body is not Genesis)
                    return Failed(TrustFailureKind.PresenceRequired, $"new device '{r.Id}' brings no Hello key");
                introduced[r.Id] = new(r.Id, owner, key!, r.Paper, r.Hello);
            }
            if (link.Body is BindHello bind)
            {
                if (!devices.TryGetValue(bind.DeviceId, out var target) || target.Paper)
                    return Failed(TrustFailureKind.InvalidLink, $"'{bind.DeviceId}' is not an active device");
                if (target.Hello is not null)
                    return Failed(TrustFailureKind.InvalidLink, $"'{bind.DeviceId}' already has a Hello key");
                if (!IsHelloKey(bind.Hello))
                    return Failed(TrustFailureKind.InvalidLink, $"invalid Hello key for '{bind.DeviceId}'");
            }
            if (link.Body is Genesis { PaperKey.Paper: false } or Genesis { Device.Paper: true } or AddUser { Device.Paper: true } or AddUser { PaperKey.Paper: false })
                return Failed(TrustFailureKind.InvalidLink, "paper key flags do not match their roles");

            // Every signature is a countersignature or an active device's authorization.
            var signed = TrustChain.SignedBytes(link);
            var presence = TrustChain.PresenceBytes(link);
            var countersigned = new HashSet<string>();
            var present = new HashSet<string>();
            var authorizers = new Dictionary<string, TrustedDevice>();
            foreach (var sig in link.Signatures)
            {
                var isNew = introduced.TryGetValue(sig.DeviceId, out var device);
                if (!isNew && !devices.TryGetValue(sig.DeviceId, out device))
                    return retired.Contains(sig.DeviceId)
                        ? Failed(TrustFailureKind.RevokedSigner, $"'{sig.DeviceId}' is revoked")
                        : Failed(TrustFailureKind.UnauthorizedSigner, $"'{sig.DeviceId}' is not a device of this chain");
                if (!Ed25519.Verify(device!.Key, signed, sig.Signature))
                    return Failed(TrustFailureKind.BadSignature, $"signature by '{sig.DeviceId}' does not verify");
                if (sig.Hello is not null)
                {
                    var hello = link.Body is BindHello b && b.DeviceId == sig.DeviceId ? b.Hello : device.Hello;
                    if (hello is null || !VerifyHello(hello, presence, sig.Hello))
                        return Failed(TrustFailureKind.BadSignature, $"Hello signature by '{sig.DeviceId}' does not verify");
                    present.Add(sig.DeviceId);
                }
                if (isNew)
                    countersigned.Add(sig.DeviceId);
                else
                    authorizers[sig.DeviceId] = device;
            }
            if (introduced.Keys.FirstOrDefault(id => !countersigned.Contains(id)) is { } missing)
                return Failed(TrustFailureKind.MissingCountersignature, $"new key '{missing}' did not sign");
            if (introduced.Values.FirstOrDefault(d => d.Hello is not null && !present.Contains(d.Id)) is { } absent)
                return Failed(TrustFailureKind.PresenceRequired, $"new device '{absent.Id}' did not sign with its Hello key");

            if (Authorize(link.Body, authorizers.Values) is { } refusal)
                return refusal with { Seq = seq };

            if (link.Body is AddDevice or AddUser or AddBroker or SetPolicy or BindHello
                && authorizers.Values.FirstOrDefault(a => !a.Paper && !present.Contains(a.Id)) is { } unseen)
                return Failed(TrustFailureKind.PresenceRequired, unseen.Hello is null
                    ? $"'{unseen.Id}' has no Hello key in the chain yet: bind one first"
                    : $"'{unseen.Id}' signed without its Hello key");

            foreach (var paper in authorizers.Values.Where(d => d.Paper))
                breakGlass.Add(new(seq, paper.Id, paper.User));

            switch (link.Body)
            {
                case Genesis g:
                    tenant = g.Tenant;
                    users[g.Admin] = new(g.Admin, Admin: true);
                    if (CheckThreshold(g.Policy, seq) is { } bad)
                        return bad;
                    policy = g.Policy;
                    break;
                case AddUser u:
                    users[u.User] = new(u.User, u.Admin);
                    break;
                case RevokeDevice r:
                    devices.Remove(r.DeviceId);
                    retired.Add(r.DeviceId);
                    break;
                case RemoveUser r:
                    users.Remove(r.User);
                    foreach (var d in devices.Values.Where(d => d.User == r.User).ToArray())
                    {
                        devices.Remove(d.Id);
                        retired.Add(d.Id);
                    }
                    if (CheckThreshold(policy, seq) is { } stranded)
                        return stranded;
                    break;
                case AddBroker b:
                    brokers[b.Broker] = b.PublicKey;
                    break;
                case SetPolicy p:
                    if (CheckThreshold(p.Policy, seq) is { } impossible)
                        return impossible;
                    policy = p.Policy;
                    break;
                case BindHello h:
                    devices[h.DeviceId] = devices[h.DeviceId] with { Hello = h.Hello };
                    break;
            }
            foreach (var d in introduced.Values)
                devices[d.Id] = d;
            return null;
        }

        /// <returns>A failure with seq 0 (the caller sets it), or <c>null</c> when the authorizers may sign this body.</returns>
        TrustFailure? Authorize(LinkBody body, ICollection<TrustedDevice> authorizers)
        {
            TrustFailure Failed(TrustFailureKind kind, string detail) => new(kind, 0, detail);

            switch (body)
            {
                case Genesis:
                    return null;
                case AddDevice d:
                    if (!users.ContainsKey(d.User))
                        return Failed(TrustFailureKind.InvalidLink, $"unknown user '{d.User}'");
                    if (authorizers.Count == 0 || authorizers.Any(a => a.User != d.User))
                        return Failed(TrustFailureKind.UnauthorizedSigner, $"add-device for '{d.User}' must be signed by their own devices only");
                    return null;
                case BindHello h:
                    var owner = devices[h.DeviceId].User;
                    if (!authorizers.Any(a => a.Id == h.DeviceId) || !authorizers.Any(a => a.Paper)
                        || authorizers.Any(a => a.User != owner || (!a.Paper && a.Id != h.DeviceId)))
                        return Failed(TrustFailureKind.UnauthorizedSigner, "bind-hello must be signed by the device itself and a paper key of its user");
                    return null;
                case RevokeDevice r:
                    if (!devices.TryGetValue(r.DeviceId, out var target))
                        return Failed(TrustFailureKind.InvalidLink, $"'{r.DeviceId}' is not an active device");
                    if (authorizers.Count == 0 || authorizers.Any(a => a.User != target.User && !IsAdmin(a)))
                        return Failed(TrustFailureKind.UnauthorizedSigner, "revoke-device must be signed by the device's user or an admin");
                    return null;
                case AddUser u when users.ContainsKey(u.User):
                    return Failed(TrustFailureKind.InvalidLink, $"user '{u.User}' already exists");
                case RemoveUser r when !users.ContainsKey(r.User):
                    return Failed(TrustFailureKind.InvalidLink, $"unknown user '{r.User}'");
                case AddBroker b when brokers.ContainsKey(b.Broker):
                    return Failed(TrustFailureKind.InvalidLink, $"broker '{b.Broker}' already added");
                default:
                    if (authorizers.Any(a => !IsAdmin(a)))
                        return Failed(TrustFailureKind.UnauthorizedSigner, "admin links must be signed by admins only");
                    var distinct = authorizers.Select(a => a.User).Distinct().Count();
                    return distinct < policy.AdminThreshold
                        ? Failed(TrustFailureKind.InsufficientAdminSignatures, $"{distinct} of {policy.AdminThreshold} admin users signed")
                        : null;
            }
        }

        bool IsAdmin(TrustedDevice device) => users.TryGetValue(device.User, out var user) && user.Admin;

        static bool IsHelloKey(byte[] spki)
        {
            using var rsa = RSA.Create();
            try
            {
                rsa.ImportSubjectPublicKeyInfo(spki, out var read);
                return read == spki.Length && rsa.KeySize >= 2048;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        static bool VerifyHello(byte[] spki, byte[] data, byte[] signature)
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out _);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>A threshold above the admin count would leave the chain unable to change again.</summary>
        TrustFailure? CheckThreshold(TrustPolicy candidate, long seq)
        {
            var admins = users.Values.Count(u => u.Admin);
            return candidate.AdminThreshold < 1 || candidate.AdminThreshold > admins
                ? new(TrustFailureKind.InvalidLink, seq, $"admin threshold {candidate.AdminThreshold} with {admins} admin(s)")
                : null;
        }
    }
}
