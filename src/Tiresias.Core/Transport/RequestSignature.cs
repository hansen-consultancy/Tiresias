using System.Text;
using NSec.Cryptography;

namespace Tiresias.Transport;

/// <summary>
/// Ed25519 signature a device (forwarder, Keyring) puts on every management request to the broker.
/// The signed bytes bind method, endpoint and timestamp to the body, so a captured signature can't
/// be replayed onto another endpoint or, past the window, at all.
/// </summary>
/// <remarks>Signed bytes: UTF-8 of <c>"{METHOD}\n{endpoint}\n{unixSeconds}\n"</c> followed by the body.</remarks>
public static class RequestSignature
{
    public const string DeviceHeader = "X-Tiresias-Device";
    public const string TimestampHeader = "X-Tiresias-Timestamp";
    public const string SignatureHeader = "X-Tiresias-Signature";

    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxSkewAhead = TimeSpan.FromMinutes(2);

    static readonly SignatureAlgorithm Ed25519 = SignatureAlgorithm.Ed25519;

    public static byte[] Sign(Key key, string method, string endpoint, long timestamp, ReadOnlySpan<byte> body) =>
        Ed25519.Sign(key, SignedBytes(method, endpoint, timestamp, body));

    public static bool Verify(PublicKey key, string method, string endpoint, long timestamp, ReadOnlySpan<byte> body, ReadOnlySpan<byte> signature, DateTimeOffset now)
    {
        var age = now - DateTimeOffset.FromUnixTimeSeconds(timestamp);
        if (age > MaxAge || age < -MaxSkewAhead)
            return false;
        return Ed25519.Verify(key, SignedBytes(method, endpoint, timestamp, body), signature);
    }

    static byte[] SignedBytes(string method, string endpoint, long timestamp, ReadOnlySpan<byte> body) =>
        [.. Encoding.UTF8.GetBytes($"{method.ToUpperInvariant()}\n{endpoint}\n{timestamp}\n"), .. body];
}
