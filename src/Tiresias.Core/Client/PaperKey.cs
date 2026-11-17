using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Tiresias.Client;

/// <summary>
/// The paper recovery key as a person handles it: RFC 4648 base32 in groups of four letters (the
/// "words" the first-run wizard asks back), and the signing key derived from it for the trust
/// chain's genesis. One sheet of paper serves both: the raw bytes are the X25519 recovery key that
/// wraps every DEK, and an HKDF of them with its own label is the Ed25519 paper key that co-signs
/// genesis, so neither use can be turned into the other.
/// </summary>
public static class PaperKey
{
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static readonly byte[] SigningInfo = "tiresias/v1/paper-signing-key"u8.ToArray();

    /// <summary>Groups of four, eight groups per line.</summary>
    public static string Format(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder();
        var written = 0;
        foreach (var c in Letters(bytes))
        {
            if (written > 0 && written % 4 == 0)
                sb.Append(written % 32 == 0 ? '\n' : ' ');
            sb.Append(c);
            written++;
        }
        return sb.ToString();
    }

    /// <summary>The four-letter groups, in order: what the wizard numbers and asks back.</summary>
    public static IReadOnlyList<string> Words(ReadOnlySpan<byte> bytes)
    {
        var letters = Letters(bytes);
        return Enumerable.Range(0, (letters.Length + 3) / 4).Select(i => letters.Substring(i * 4, Math.Min(4, letters.Length - i * 4))).ToArray();
    }

    /// <summary>Reads a typed key back, forgiving case, spaces, line breaks and dashes.</summary>
    /// <returns>The bytes, or <c>null</c> when the text is not a key of <paramref name="length"/> bytes.</returns>
    public static byte[]? Parse(string text, int length = 32)
    {
        var bits = 0;
        var buffer = 0;
        var bytes = new List<byte>();
        foreach (var raw in text)
        {
            if (char.IsWhiteSpace(raw) || raw == '-')
                continue;
            var value = Alphabet.IndexOf(char.ToUpperInvariant(raw), StringComparison.Ordinal);
            if (value < 0)
                return null;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
            buffer &= (1 << bits) - 1;
        }
        return bytes.Count == length ? [.. bytes] : null;
    }

    /// <summary>
    /// Two distinct word positions (0-based) to ask back, so a key that was never written down is
    /// caught before anything depends on it.
    /// </summary>
    public static (int First, int Second) Challenge(int wordCount, Func<int, int>? random = null)
    {
        random ??= RandomNumberGenerator.GetInt32;
        var first = random(wordCount);
        var second = random(wordCount - 1);
        if (second >= first)
            second++;
        return first < second ? (first, second) : (second, first);
    }

    /// <summary>Whether the typed answers match the words at the challenged positions (case and spaces ignored).</summary>
    public static bool Confirm(IReadOnlyList<string> words, (int First, int Second) challenge, string first, string second) =>
        Same(words[challenge.First], first) && Same(words[challenge.Second], second);

    /// <summary>The Ed25519 paper key that co-signs genesis, derived from the recovery key's raw bytes.</summary>
    public static Key SigningKey(ReadOnlySpan<byte> recoveryKey)
    {
        var seed = HKDF.DeriveKey(HashAlgorithmName.SHA256, recoveryKey.ToArray(), 32, salt: [], info: SigningInfo);
        try
        {
            return Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        }
        finally
        {
            Array.Clear(seed);
        }
    }

    /// <summary>Whether <paramref name="recoveryKey"/> is the private half of the stored public one.</summary>
    public static bool Matches(ReadOnlySpan<byte> recoveryKey, byte[] publicKey)
    {
        using var key = Key.Import(KeyAgreementAlgorithm.X25519, recoveryKey, KeyBlobFormat.RawPrivateKey);
        return CryptographicOperations.FixedTimeEquals(key.PublicKey.Export(KeyBlobFormat.RawPublicKey), publicKey);
    }

    static bool Same(string expected, string typed) =>
        string.Equals(expected, new string(typed.Where(c => !char.IsWhiteSpace(c)).ToArray()), StringComparison.OrdinalIgnoreCase);

    static string Letters(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0)
            sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }
}
