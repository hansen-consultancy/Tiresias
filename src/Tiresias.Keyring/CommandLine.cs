using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Tiresias.Keyring;

/// <summary>Positional arguments, <c>--name value</c> / <c>--flag</c> options, and everything after a bare <c>--</c> untouched.</summary>
sealed class CommandLine
{
    readonly List<string> positional = [];
    readonly Dictionary<string, List<string?>> options = new(StringComparer.Ordinal);

    public CommandLine(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--")
            {
                Rest = args[(i + 1)..];
                break;
            }
            if (!args[i].StartsWith("--", StringComparison.Ordinal))
                positional.Add(args[i]);
            else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                Add(args[i], args[++i]);
            else
                Add(args[i], null);
        }
    }

    /// <summary>The arguments after <c>--</c>, e.g. the command <c>tir exec</c> runs.</summary>
    public IReadOnlyList<string> Rest { get; } = [];

    public string? At(int index) => index < positional.Count ? positional[index] : null;

    public string Require(int index, string name) => At(index) ?? throw new UsageException($"Missing <{name}>.");

    /// <summary>The option's value; the last one when it was given more than once.</summary>
    public string? Option(string name) => options.GetValueOrDefault(name)?[^1];

    /// <summary>Every value of an option that may repeat, e.g. <c>--method GET --method POST</c>.</summary>
    public IReadOnlyList<string> Options(string name) => options.GetValueOrDefault(name)?.OfType<string>().ToArray() ?? [];

    public string Require(string name) =>
        Option(name) is { Length: > 0 } value ? value : throw new UsageException($"Missing {name} <value>.");

    public bool Flag(string name) => options.ContainsKey(name);

    void Add(string name, string? value)
    {
        if (!options.TryGetValue(name, out var values))
            options[name] = values = [];
        values.Add(value);
    }
}

sealed class UsageException(string message) : Exception(message);

static class Terminal
{
    static readonly Regex Duration = new(@"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$", RegexOptions.CultureInvariant);

    /// <summary><c>15m</c>, <c>1h</c>, <c>1h30m</c>, <c>90s</c>, or a .NET <c>hh:mm:ss</c>.</summary>
    public static TimeSpan ParseDuration(string text)
    {
        var match = Duration.Match(text);
        if (text.Length > 0 && match.Success)
            return new TimeSpan(Number(1), Number(2), Number(3));
        return TimeSpan.TryParse(text, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : throw new UsageException($"Can't read duration '{text}'. Use e.g. 15m, 1h or 1h30m.");

        int Number(int group) => match.Groups[group].Success ? int.Parse(match.Groups[group].Value, CultureInfo.InvariantCulture) : 0;
    }

    /// <summary>A line typed without echo, as UTF-8. The caller zeroes it.</summary>
    public static byte[] ReadHidden(string prompt)
    {
        if (Console.IsInputRedirected)
            throw new UsageException("Input is redirected; use --from-stdin.");
        Console.Write(prompt);
        var chars = new List<char>();
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                    break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (chars.Count > 0)
                        chars.RemoveAt(chars.Count - 1);
                }
                else if (key.KeyChar != '\0')
                    chars.Add(key.KeyChar);
            }
            Console.WriteLine();
            var array = chars.ToArray();
            var bytes = Encoding.UTF8.GetBytes(array);
            Array.Clear(array);
            return bytes;
        }
        finally
        {
            chars.Clear();
            chars.TrimExcess();
        }
    }

    /// <summary>All of standard input as bytes, without a trailing line break. The caller zeroes it.</summary>
    public static byte[] ReadStdin()
    {
        using var buffer = new MemoryStream();
        Console.OpenStandardInput().CopyTo(buffer);
        var bytes = buffer.GetBuffer();
        var length = (int)buffer.Length;
        while (length > 0 && bytes[length - 1] is (byte)'\n' or (byte)'\r')
            length--;
        var value = bytes[..length];
        Array.Clear(bytes);
        return value;
    }

    public static bool Confirm(string question)
    {
        Console.Write($"{question} [y/N] ");
        return Console.ReadLine()?.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) == true;
    }
}
