using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Client;

/// <summary>
/// A name found beside a value, and what was seen of the value before it was dropped. Never the value.
/// </summary>
/// <param name="IsReference">The value is taken from elsewhere when used (<c>${localEnv:X}</c>, <c>$X</c>, <c>%X%</c>): nothing secret sits in the file.</param>
/// <param name="HasPassword">The value is a URL with a password in it (<c>postgres://u:p@h/db</c>), whatever the name.</param>
public readonly record struct ScannedName(string Name, bool Empty, bool IsReference, bool IsPath, bool HasPassword)
{
    /// <summary>A value written in the file itself.</summary>
    public bool Literal => !Empty && !IsReference;

    /// <summary>The host's rule for secret-looking variables (<see cref="SealedVariables.LooksSecret"/>), or a password in a URL.</summary>
    public bool LooksSecret => Literal && (HasPassword || SealedVariables.LooksSecret(Name, 1, IsPath));

    /// <summary>The name as a finding shows it.</summary>
    public string Shown => HasPassword ? $"{Name} (password in URL)" : Name;
}

public delegate T SpanScanner<out T>(ReadOnlySpan<byte> text);

/// <summary>
/// Names from files that hold values (docs/containers-and-vms.md, "Names only"): a scanner reads
/// bytes, keeps each name and a few facts about its value, and never makes a string of a value.
/// The bytes are cleared once scanned.
/// </summary>
public static class NameScan
{
    /// <summary>Larger files are not read: no <c>.env</c> or <c>devcontainer.json</c> is this big.</summary>
    public const int MaxBytes = 1 << 20;

    /// <summary>Reads at most <see cref="MaxBytes"/> into a pooled buffer, scans it, and clears it. A larger stream is scanned as empty.</summary>
    public static T Read<T>(Stream stream, SpanScanner<T> scan)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(MaxBytes + 1);
        try
        {
            var read = stream.ReadAtLeast(buffer.AsSpan(0, MaxBytes + 1), MaxBytes + 1, throwOnEndOfStream: false);
            return read > MaxBytes ? Consume(buffer.AsSpan(0, read), _ => scan([])) : Consume(buffer.AsSpan(0, read), scan);
        }
        finally
        {
            // A read that failed half way left bytes Consume never saw.
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <inheritdoc cref="Read"/>
    public static async Task<T> ReadAsync<T>(Stream stream, SpanScanner<T> scan, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(MaxBytes + 1);
        try
        {
            var read = await stream.ReadAtLeastAsync(buffer.AsMemory(0, MaxBytes + 1), MaxBytes + 1, throwOnEndOfStream: false, ct);
            return read > MaxBytes ? Consume(buffer.AsSpan(0, read), _ => scan([])) : Consume(buffer.AsSpan(0, read), scan);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Scans the bytes, past a UTF-8 byte order mark, then clears them, whatever the scan did.</summary>
    public static T Consume<T>(Span<byte> buffer, SpanScanner<T> scan)
    {
        try
        {
            ReadOnlySpan<byte> text = buffer;
            return scan(text.StartsWith("﻿"u8) ? text[3..] : text);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary><c>NAME=value</c> lines, as in <c>.env</c> and <c>--env-file</c> files: <c>#</c> comments and <c>export</c> allowed, anything else skipped.</summary>
    public static IReadOnlyList<ScannedName> EnvLines(ReadOnlySpan<byte> text)
    {
        List<ScannedName> names = [];
        foreach (var range in text.Split((byte)'\n'))
        {
            var line = text[range].Trim("\r \t"u8);
            if (line.StartsWith("export "u8))
                line = line[7..].TrimStart(" \t"u8);
            if (!line.IsEmpty && line[0] != '#' && Entry(line) is { } name)
                names.Add(name);
        }
        return names;
    }

    /// <summary>One <c>NAME=value</c>; <c>null</c> when it has no <c>=</c> or no valid name.</summary>
    public static ScannedName? Entry(ReadOnlySpan<byte> entry)
    {
        var equals = entry.IndexOf((byte)'=');
        if (equals <= 0)
            return null;
        var name = entry[..equals].Trim(" \t"u8);
        return IsName(name) ? Facts(Encoding.UTF8.GetString(name), entry[(equals + 1)..]) : null;
    }

    /// <summary>The name with what is seen of the value: the value itself goes no further than this method.</summary>
    public static ScannedName Facts(string name, ReadOnlySpan<byte> value)
    {
        value = value.Trim(" \t"u8);
        if (value.Length >= 2 && value[0] is (byte)'"' or (byte)'\'' && value[^1] == value[0])
            value = value[1..^1];
        var path = value.StartsWith("/"u8) || value.StartsWith("~"u8) || value.StartsWith("./"u8) || value.StartsWith("../"u8) || value.StartsWith(@"\\"u8)
            || (value.Length >= 3 && char.IsAsciiLetter((char)value[0]) && value[1] == ':' && value[2] is (byte)'\\' or (byte)'/');
        return new(name, value.IsEmpty, !value.IsEmpty && value[0] is (byte)'$' or (byte)'%', path, HasPassword(value));
    }

    static bool HasPassword(ReadOnlySpan<byte> value)
    {
        var scheme = value.IndexOf("://"u8);
        if (scheme <= 0)
            return false;
        var rest = value[(scheme + 3)..];
        var end = rest.IndexOfAny("/?#"u8);
        var authority = end < 0 ? rest : rest[..end];
        var at = authority.LastIndexOf((byte)'@');
        var colon = at < 0 ? -1 : authority[..at].IndexOf((byte)':');
        return colon > 0 && colon < at - 1;
    }

    static bool IsName(ReadOnlySpan<byte> name) =>
        name.Length is > 0 and <= 256 && !name.ContainsAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"u8);
}
