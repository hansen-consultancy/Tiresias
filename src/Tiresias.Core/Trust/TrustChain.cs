using System.Security.Cryptography;
using NSec.Cryptography;

namespace Tiresias.Trust;

/// <summary>
/// Builds links. Building enforces nothing beyond seq/prev bookkeeping; whether a link is allowed is
/// <see cref="TrustChainVerifier"/>'s call alone.
/// </summary>
public static class TrustChain
{
    public static readonly string ZeroHash = new('0', 64);

    /// <summary>Genesis: the first admin's device and their paper key both sign it.</summary>
    public static TrustLink Start(string tenant, string admin, Signer device, Signer paperKey, TrustPolicy policy, DateTimeOffset time) =>
        Link(0, ZeroHash, time, new Genesis(tenant, admin, device.Describe(), paperKey.Describe(paper: true), policy), device, paperKey);

    /// <param name="signers">The authorizing device(s) plus every key the body introduces, which must countersign.</param>
    public static TrustLink Append(IReadOnlyList<TrustLink> chain, LinkBody body, DateTimeOffset time, params Signer[] signers) =>
        Link(chain.Count, Hash(chain[^1]), time, body, signers);

    /// <summary>A link with arbitrary seq and prev, signed as given.</summary>
    public static TrustLink Link(long seq, string prev, DateTimeOffset time, LinkBody body, params Signer[] signers)
    {
        var link = new TrustLink(seq, prev, DateTimeOffset.FromUnixTimeSeconds(time.ToUnixTimeSeconds()), body, []);
        return signers.Aggregate(link, Cosign);
    }

    /// <summary>Adds one more signature, e.g. a second admin's for an M-of-N link collected separately.</summary>
    public static TrustLink Cosign(TrustLink link, Signer signer) => link with
    {
        Signatures = [.. link.Signatures, new(signer.DeviceId, SignatureAlgorithm.Ed25519.Sign(signer.Key, SignedBytes(link)))],
    };

    /// <summary>The bytes every signature on the link covers.</summary>
    public static byte[] SignedBytes(TrustLink link) => TrustLinkJson.Write(link, withSignatures: false);

    /// <summary>Lowercase hex SHA-256 of the link's full canonical form, signatures included.</summary>
    public static string Hash(TrustLink link) => Convert.ToHexStringLower(SHA256.HashData(TrustLinkJson.Write(link, withSignatures: true)));
}
