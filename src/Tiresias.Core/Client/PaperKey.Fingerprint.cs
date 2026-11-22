using System.Security.Cryptography;

namespace Tiresias.Client;

public static partial class PaperKey
{
    public static string PublicFingerprint(ReadOnlySpan<byte> publicKey) => Convert.ToHexString(SHA256.HashData(publicKey));
}
