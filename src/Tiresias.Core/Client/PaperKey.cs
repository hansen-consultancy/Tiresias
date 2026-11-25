using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Tiresias.Client;

/// <summary>A typed paper key, and the lookalike letters read differently to match a known key.</summary>
/// <param name="Key">The key's bytes; the caller owns and clears them.</param>
/// <param name="Corrections">Empty when the key was taken as typed.</param>
public sealed record PaperKeyReading(byte[] Key, IReadOnlyList<PaperKeyCorrection> Corrections);

/// <summary>A letter read differently: <paramref name="Typed"/> in four-letter group <paramref name="Group"/> (1-based) was read as <paramref name="Read"/>.</summary>
public readonly record struct PaperKeyCorrection(int Group, char Typed, char Read)
{
    public override string ToString() => $"group {Group}: {Typed} as {Read}";
}

/// <summary>
/// The paper recovery key as a person handles it: RFC 4648 base32 in groups of four letters (the
/// "words" the first-run wizard asks back), and the signing key derived from it for the trust
/// chain's genesis. One sheet of paper serves both: the raw bytes are the X25519 recovery key that
/// wraps every DEK, and an HKDF of them with its own label is the Ed25519 paper key that co-signs
/// genesis, so neither use can be turned into the other.
/// </summary>
public static partial class PaperKey
{
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static readonly byte[] SigningInfo = "tiresias/v1/paper-signing-key"u8.ToArray();
    const int MaxReadings = 1 << 12;

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

    /// <summary>Reads a typed key back, forgiving case, spaces, line breaks, dashes and the digits 0, 1 and 8 for O, I and B.</summary>
    /// <returns>The bytes, or <c>null</c> when the text is not a key of <paramref name="length"/> bytes.</returns>
    public static byte[]? Parse(string text, int length = 32)
    {
        var letters = Letters(text);
        if (letters is null)
            return null;
        try
        {
            return Decode(letters, length);
        }
        finally
        {
            Array.Clear(letters);
        }
    }

    /// <summary>
    /// Reads a typed key as <see cref="Parse"/> does, and when <paramref name="known"/> rejects it,
    /// reads its lookalike letters (S/5, Z/2, T/7, U/V) the other way: fewest swaps first, at most
    /// 4096 readings. A swapped reading is taken only when <paramref name="known"/> accepts it and no
    /// other reading with as few swaps does. <paramref name="known"/> gets each reading's bytes, which
    /// are cleared after it returns.
    /// </summary>
    /// <returns>
    /// <c>null</c> when the text is not a key of <paramref name="length"/> bytes. Otherwise the proven
    /// reading with what was read differently, or, when none is proven, the key as typed with no
    /// corrections, for the caller's own checks to judge.
    /// </returns>
    public static PaperKeyReading? Read(string text, Func<byte[], bool> known, int length = 32)
    {
        var letters = Letters(text);
        if (letters is null)
            return null;
        try
        {
            var typed = Decode(letters, length);
            if (typed is null)
                return null;
            if (known(typed))
                return new(typed, []);
            var proven = Swapped(letters, typed, known, length);
            if (proven is null)
                return new(typed, []);
            Array.Clear(typed);
            return proven;
        }
        finally
        {
            Array.Clear(letters);
        }
    }

    static PaperKeyReading? Swapped(char[] letters, byte[] typed, Func<byte[], bool> known, int length)
    {
        var positions = Enumerable.Range(0, letters.Length).Where(i => Lookalike(letters[i]) is not null).ToArray();
        var reading = new char[letters.Length];
        var tried = 0;
        try
        {
            for (var swaps = 1; swaps <= positions.Length; swaps++)
            {
                byte[]? found = null;
                int[]? foundAt = null;
                var ambiguous = false;
                foreach (var subset in Subsets(positions, swaps))
                {
                    // An unfinished round can't rule out a second match, so it proves nothing.
                    if (++tried > MaxReadings)
                    {
                        if (found is not null)
                            Array.Clear(found);
                        return null;
                    }
                    letters.CopyTo(reading, 0);
                    foreach (var i in subset)
                        reading[i] = Lookalike(reading[i])!.Value;
                    var candidate = Decode(reading, length)!;
                    // The last letter's spare bits never reach the bytes, so some swaps read the same key.
                    if (candidate.AsSpan().SequenceEqual(typed) || (found is not null && candidate.AsSpan().SequenceEqual(found)) || !known(candidate))
                    {
                        Array.Clear(candidate);
                        continue;
                    }
                    if (found is null)
                    {
                        found = candidate;
                        foundAt = subset;
                    }
                    else
                    {
                        Array.Clear(candidate);
                        ambiguous = true;
                    }
                }
                if (found is null)
                    continue;
                if (ambiguous)
                {
                    Array.Clear(found);
                    return null;
                }
                return new(found, [.. foundAt!.Select(i => new PaperKeyCorrection(i / 4 + 1, letters[i], Lookalike(letters[i])!.Value))]);
            }
            return null;
        }
        finally
        {
            Array.Clear(reading);
        }
    }

    /// <summary>Every <paramref name="size"/>-element subset of <paramref name="items"/>.</summary>
    static IEnumerable<int[]> Subsets(int[] items, int size)
    {
        var at = Enumerable.Range(0, size).ToArray();
        while (true)
        {
            yield return [.. at.Select(i => items[i])];
            var k = size - 1;
            while (k >= 0 && at[k] == items.Length - size + k)
                k--;
            if (k < 0)
                yield break;
            at[k]++;
            for (var j = k + 1; j < size; j++)
                at[j] = at[j - 1] + 1;
        }
    }

    /// <summary>The typed letters in canonical form, or <c>null</c> when one is outside the alphabet.</summary>
    static char[]? Letters(string text)
    {
        var letters = new char[text.Length];
        var count = 0;
        foreach (var raw in text)
        {
            if (char.IsWhiteSpace(raw) || raw == '-')
                continue;
            var c = Letter(raw);
            if (!Alphabet.Contains(c, StringComparison.Ordinal))
            {
                Array.Clear(letters);
                return null;
            }
            letters[count++] = c;
        }
        var result = letters[..count];
        Array.Clear(letters);
        return result;
    }

    static byte[]? Decode(ReadOnlySpan<char> letters, int length)
    {
        if (letters.Length * 5 / 8 != length)
            return null;
        var bits = 0;
        var buffer = 0;
        var bytes = new byte[length];
        var count = 0;
        foreach (var c in letters)
        {
            buffer = (buffer << 5) | Alphabet.IndexOf(c, StringComparison.Ordinal);
            bits += 5;
            if (bits >= 8)
            {
                bytes[count++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
            buffer &= (1 << bits) - 1;
        }
        return bytes;
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

    /// <summary>The public recipient fingerprint to compare with the administrator's enrollment prompt.</summary>
    public static string RecipientFingerprint(ReadOnlySpan<byte> paper)
    {
        using var key = Key.Import(KeyAgreementAlgorithm.X25519, paper, KeyBlobFormat.RawPrivateKey);
        return PublicFingerprint(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>The expected word is known, so a lookalike letter typed for it is a misread, not another key.</summary>
    static bool Same(string expected, string typed)
    {
        var letters = typed.Where(c => !char.IsWhiteSpace(c)).Select(Letter).ToArray();
        return letters.Length == expected.Length && letters.Zip(expected).All(p => p.First == p.Second || Lookalike(p.First) == p.Second);
    }

    /// <summary>
    /// Pairs of real alphabet symbols that handwriting and fonts blur. Unlike 0, 1 and 8 neither side
    /// can be ruled out by parsing, so a swap needs proof (<see cref="Read"/>).
    /// </summary>
    static char? Lookalike(char c) => c switch
    {
        'S' => '5',
        '5' => 'S',
        'Z' => '2',
        '2' => 'Z',
        'T' => '7',
        '7' => 'T',
        'U' => 'V',
        'V' => 'U',
        _ => null,
    };

    /// <summary>
    /// The alphabet has no 0, 1 or 8, so a typed digit can only be a misread O, I or B. Handwriting
    /// and many fonts blur those, and a refused copy of a correct key is worse than no check.
    /// </summary>
    static char Letter(char typed) => char.ToUpperInvariant(typed) switch
    {
        '0' => 'O',
        '1' => 'I',
        '8' => 'B',
        var c => c,
    };

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
