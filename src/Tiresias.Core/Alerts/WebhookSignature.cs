using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Tiresias.Alerts;

/// <summary>
/// Signs a webhook delivery the <a href="https://www.standardwebhooks.com/">Standard Webhooks</a> way
/// (docs/alerts.md, <i>Signed webhooks</i>), so a receiver can check it with an off-the-shelf library:
/// <c>webhook-signature: v1,&lt;base64 HMAC-SHA-256 over "id.timestamp.body"&gt;</c>, keyed by a
/// <c>whsec_</c> secret sealed in <c>alerts.json</c>. Pure.
/// </summary>
public static class WebhookSignature
{
    public const string IdHeader = "webhook-id";
    public const string TimestampHeader = "webhook-timestamp";
    public const string SignatureHeader = "webhook-signature";
    public const string SecretPrefix = "whsec_";

    /// <summary>How far a receiver should let <c>webhook-timestamp</c> stray from its own clock: the spec's default.</summary>
    public static readonly TimeSpan Tolerance = TimeSpan.FromMinutes(5);

    /// <summary>A fresh secret: <c>whsec_</c> and 32 random bytes in base64.</summary>
    public static string NewSecret() => SecretPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    /// <summary>The key in <paramref name="secret"/>: <c>whsec_</c> and base64 of 24 to 64 bytes, as the spec allows.</summary>
    public static bool TryParseSecret(string secret, out byte[] key)
    {
        key = [];
        if (!secret.StartsWith(SecretPrefix, StringComparison.Ordinal))
            return false;
        var buffer = new byte[64];
        if (!Convert.TryFromBase64String(secret[SecretPrefix.Length..], buffer, out var length) || length is < 24 or > 64)
            return false;
        key = buffer[..length];
        return true;
    }

    /// <summary>The three headers for one attempt. <paramref name="id"/> is the payload's id; a retry signs again with its own time.</summary>
    /// <exception cref="ArgumentException"><paramref name="secret"/> is not a <c>whsec_</c> secret.</exception>
    public static IReadOnlyList<KeyValuePair<string, string>> Headers(string secret, string id, DateTimeOffset now, ReadOnlySpan<byte> body)
    {
        if (!TryParseSecret(secret, out var key))
            throw new ArgumentException("Not a signing secret.", nameof(secret));
        var timestamp = now.ToUnixTimeSeconds();
        return
        [
            KeyValuePair.Create(IdHeader, id),
            KeyValuePair.Create(TimestampHeader, timestamp.ToString(CultureInfo.InvariantCulture)),
            KeyValuePair.Create(SignatureHeader, Sign(key, id, timestamp, body)),
        ];
    }

    /// <summary><c>v1,</c> and base64 of HMAC-SHA-256 under <paramref name="key"/> over <c>id.timestamp.body</c>.</summary>
    public static string Sign(byte[] key, string id, long timestamp, ReadOnlySpan<byte> body)
    {
        var prefix = Encoding.UTF8.GetBytes($"{id}.{timestamp.ToString(CultureInfo.InvariantCulture)}.");
        var signed = new byte[prefix.Length + body.Length];
        prefix.CopyTo(signed, 0);
        body.CopyTo(signed.AsSpan(prefix.Length));
        return "v1," + Convert.ToBase64String(HMACSHA256.HashData(key, signed));
    }
}
