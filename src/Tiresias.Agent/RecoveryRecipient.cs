using System.Globalization;
using System.Numerics;

namespace Tiresias.Agent;

internal enum RecoveryEnrollmentResult { Applied = 0, Declined = 3 }

internal sealed record RecoveryBinding(Guid Revision, string PublicKey);

internal static class RecoveryRecipient
{
    // The two order-eight u-coordinates from the X25519 low-order blocklist (libsodium ref10).
    static readonly BigInteger OrderEightA = BigInteger.Parse("325606250916557431795983626356110631294008115727848805560023387167927233504", CultureInfo.InvariantCulture);
    static readonly BigInteger OrderEightB = BigInteger.Parse("39382357235489614581723060781553021112529911719440698176882885853963445705823", CultureInfo.InvariantCulture);
    static readonly BigInteger PrimeMinusOne = (BigInteger.One << 255) - 20;

    internal static void ValidateKey(string key)
    {
        Span<byte> raw = stackalloc byte[32];
        if (key is not { Length: 44 } || !Convert.TryFromBase64String(key, raw, out var count) || count != raw.Length ||
            Convert.ToBase64String(raw) != key)
            throw new InvalidOperationException("Invalid recovery recipient.");
        // Enroll the unique canonical public encoding emitted by key generation. 0, 1 and p-1 also have low order.
        var u = new BigInteger(raw, isUnsigned: true, isBigEndian: false);
        if (u <= BigInteger.One || u >= PrimeMinusOne || u == OrderEightA || u == OrderEightB)
            throw new InvalidOperationException("Invalid recovery recipient.");
    }

    internal static bool UserSid(string? sid)
    {
        if (sid is null || sid.Length > 53 || !(sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) ||
            sid.StartsWith("S-1-12-1-", StringComparison.Ordinal)))
            return false;
        var parts = sid[9..].Split('-');
        return parts.Length == 4 && parts.All(part => uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var component) &&
            component.ToString(CultureInfo.InvariantCulture) == part);
    }
}
