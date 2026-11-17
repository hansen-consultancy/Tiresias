using System.Security.Cryptography;
using System.Text;

namespace Tiresias.Access;

/// <summary>
/// A placeholder as the broker stores it: only the token's hash, plus the approved request it was
/// minted for. The token itself is returned once, at minting.
/// </summary>
public sealed record Placeholder(
    byte[] TokenHash,
    string LeaseId,
    AccessRequest Request,
    DateTimeOffset ExpiresAt);

public static class PlaceholderToken
{
    /// <summary>Greppable prefix, so leaked tokens are easy to scan for in logs, commits and agent output.</summary>
    public const string Prefix = "tirph_";

    /// <summary>Format <c>tirph_{service}_{base32 of 128 random bits}</c>. The service part is a hint for people, never trusted.</summary>
    public static string Mint(string serviceSlug) =>
        $"{Prefix}{serviceSlug}_{Base32(RandomNumberGenerator.GetBytes(16))}";

    public static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    static string Base32(byte[] bytes)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var sb = new StringBuilder((bytes.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
            sb.Append(alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }
}

public enum PlaceholderRejection
{
    None,
    Unknown,
    Expired,
    LeaseEnded,
}

/// <summary>
/// In-memory placeholder table for one broker process. Lives and dies with the broker's RAM, like
/// the lease keys: a restart invalidates every placeholder, which is the point.
/// </summary>
public sealed class PlaceholderRegistry(TimeProvider time)
{
    readonly Dictionary<string, Placeholder> byHash = [];
    readonly Lock gate = new();

    /// <returns>The token, which is not stored and can't be recovered later.</returns>
    public string Mint(string leaseId, AccessRequest request, DateTimeOffset leaseEndsAt)
    {
        var token = PlaceholderToken.Mint(request.ServiceSlug);
        var hash = PlaceholderToken.Hash(token);
        var requested = time.GetUtcNow() + request.Duration;
        var expires = requested < leaseEndsAt ? requested : leaseEndsAt;
        lock (gate)
            byHash[Convert.ToHexString(hash)] = new(hash, leaseId, request, expires);
        return token;
    }

    /// <param name="activeLeaseId">The broker's current lease, or <c>null</c> when none is open.</param>
    public (Placeholder? Placeholder, PlaceholderRejection Rejection) Resolve(string token, string? activeLeaseId)
    {
        var hash = PlaceholderToken.Hash(token);
        Placeholder? found;
        lock (gate)
            byHash.TryGetValue(Convert.ToHexString(hash), out found);

        // The dictionary lookup is by hash, so comparing the hash again in fixed time only guards
        // against a future change of the lookup key; it costs nothing.
        if (found is null || !CryptographicOperations.FixedTimeEquals(found.TokenHash, hash))
            return (null, PlaceholderRejection.Unknown);
        if (found.LeaseId != activeLeaseId)
            return (null, PlaceholderRejection.LeaseEnded);
        if (time.GetUtcNow() >= found.ExpiresAt)
            return (null, PlaceholderRejection.Expired);
        return (found, PlaceholderRejection.None);
    }

    /// <returns>The placeholder dropped, or <c>null</c> when the token was unknown.</returns>
    public Placeholder? Revoke(string token)
    {
        lock (gate)
            return byHash.Remove(Convert.ToHexString(PlaceholderToken.Hash(token)), out var removed) ? removed : null;
    }

    /// <summary>Drops every placeholder of a lease. Called when the lease ends.</summary>
    public int RevokeLease(string leaseId)
    {
        lock (gate)
        {
            var doomed = byHash.Where(p => p.Value.LeaseId == leaseId).Select(p => p.Key).ToArray();
            foreach (var key in doomed)
                byHash.Remove(key);
            return doomed.Length;
        }
    }
}
