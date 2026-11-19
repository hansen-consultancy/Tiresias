using System.Text.RegularExpressions;

namespace Tiresias.EnvironmentVariables;

/// <summary>
/// A credential in an <c>.npmrc</c> line: its <paramref name="Key"/> as written
/// (<c>//registry.npmjs.org/:_authToken</c>), the registry it is for, and the name to seal it under.
/// <paramref name="Literal"/> says the value is the credential itself rather than a <c>${NAME}</c>
/// reference npm fills in from the environment.
/// </summary>
public sealed record NpmCredential(string Key, string Registry, string Variable, bool Literal);

/// <summary>
/// Reads and edits <c>.npmrc</c> files, npm's own <c>key=value</c> format. Lines are matched by key;
/// everything else in the file, line endings included, stays as it was.
/// </summary>
public static partial class NpmRc
{
    /// <summary>The registry npm uses when the file names none.</summary>
    public const string DefaultRegistry = "registry.npmjs.org";

    static readonly (string Field, string Suffix)[] Fields = [("_authToken", "_TOKEN"), ("_password", "_PASSWORD"), ("_auth", "_AUTH")];

    /// <summary>Every credential line, the last of each key only, as npm reads it. Empty values aren't credentials.</summary>
    public static IReadOnlyList<NpmCredential> Read(string text)
    {
        var entries = Entries(text).ToArray();
        var registry = entries.LastOrDefault(e => e.Key == "registry").Value is { Length: > 0 } named ? RegistryOf(named) : DefaultRegistry;
        return [.. entries.GroupBy(e => e.Key).Select(g => g.Last())
            .Select(e => (e.Key, e.Value, Field: Fields.FirstOrDefault(f => FieldOf(e.Key) == f.Field)))
            .Where(e => e.Field.Field is not null && e.Value.Length > 0)
            .Select(e =>
            {
                var at = e.Key.Length > e.Field.Field.Length ? RegistryOf(e.Key[..^(e.Field.Field.Length + 1)]) : registry;
                return new NpmCredential(e.Key, at, VariableFor(at, e.Field.Suffix), !e.Value.Contains("${", StringComparison.Ordinal));
            })];
    }

    /// <summary>The value npm reads for <paramref name="key"/> (the last line wins), unquoted; <c>null</c> when there is none.</summary>
    public static string? ValueOf(string text, string key) =>
        Entries(text).LastOrDefault(e => e.Key == key).Value is { Length: > 0 } value ? value : null;

    /// <summary><paramref name="text"/> with every line for <paramref name="key"/> set to <c>${<paramref name="variable"/>}</c>.</summary>
    public static string WithReference(string text, string key, string variable) =>
        string.Concat(Lines(text).Select(line => Entry().Match(line) is { Success: true } m && m.Groups["key"].Value == key
            ? line[..m.Groups["value"].Index] + "${" + variable + "}" + line[(m.Groups["value"].Index + m.Groups["value"].Length)..]
            : line));

    /// <summary><c>//registry.npmjs.org/</c> or <c>https://registry.npmjs.org/</c> as <c>registry.npmjs.org</c>.</summary>
    static string RegistryOf(string value)
    {
        var at = value.Trim();
        var scheme = at.IndexOf("://", StringComparison.Ordinal);
        at = scheme >= 0 ? at[(scheme + 3)..] : at.TrimStart('/');
        return at.TrimEnd('/');
    }

    /// <summary><c>NPM_TOKEN</c> for npm's own registry, <c>NPM_NPM_PKG_GITHUB_COM_TOKEN</c> for another.</summary>
    static string VariableFor(string registry, string suffix) =>
        registry == DefaultRegistry ? "NPM" + suffix
            : "NPM_" + new string([.. registry.ToUpperInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_')]).Trim('_') + suffix;

    static string FieldOf(string key) => key[(key.LastIndexOf(':', StringComparison.Ordinal) + 1)..];

    static IEnumerable<(string Key, string Value)> Entries(string text) =>
        Lines(text).Select(line => Entry().Match(line)).Where(m => m.Success).Select(m => (m.Groups["key"].Value, Unquote(m.Groups["value"].Value)));

    static string Unquote(string value) =>
        value.Length >= 2 && value[0] is '"' or '\'' && value[^1] == value[0] ? value[1..^1] : value;

    /// <summary>The lines with their endings, so joining them gives the text back.</summary>
    internal static IEnumerable<string> Lines(string text) => LineBreak().Split(text).Where(l => l.Length > 0);

    [GeneratedRegex(@"(?<=\n)")]
    private static partial Regex LineBreak();

    /// <remarks>
    /// A key never holds a quote, <c>$</c> or a backtick (npm's never do): keys are printed inside a
    /// command to copy, and a project's file could otherwise smuggle shell syntax into it.
    /// </remarks>
    [GeneratedRegex(@"^[ \t]*(?<key>[^;#\s=""'$`][^=\r\n""'$`]*?)[ \t]*=[ \t]*(?<value>[^\r\n]*?)[ \t]*\r?\n?$")]
    private static partial Regex Entry();
}

/// <summary>A <c>[section]</c> of a <c>.pypirc</c> holding a password.</summary>
public sealed record PyPiCredential(string Section);

/// <summary>Reads and edits <c>.pypirc</c> files, the INI format twine reads its repositories from.</summary>
public static partial class PyPiRc
{
    /// <summary>The section twine uploads to by default; its password can be sealed as <see cref="Variable"/>.</summary>
    public const string DefaultSection = "pypi";

    /// <summary>The variable twine reads a password from, for whichever repository it uploads to.</summary>
    public const string Variable = "TWINE_PASSWORD";

    /// <summary>Every section with a non-empty <c>password</c>, in file order.</summary>
    public static IReadOnlyList<PyPiCredential> Read(string text) =>
        [.. Passwords(text).Where(p => p.Value.Length > 0).Select(p => p.Section).Distinct(StringComparer.OrdinalIgnoreCase).Select(s => new PyPiCredential(s))];

    /// <summary>The password in <paramref name="section"/>, or <c>null</c>.</summary>
    public static string? PasswordOf(string text, string section) =>
        Passwords(text).LastOrDefault(p => string.Equals(p.Section, section, StringComparison.OrdinalIgnoreCase)).Value is { Length: > 0 } value ? value : null;

    /// <summary><paramref name="text"/> without the password lines of <paramref name="section"/>.</summary>
    public static string WithoutPassword(string text, string section)
    {
        string? current = null;
        return string.Concat(NpmRc.Lines(text).Where(line =>
        {
            if (Section().Match(line) is { Success: true } header)
                current = header.Groups["name"].Value;
            return !(string.Equals(current, section, StringComparison.OrdinalIgnoreCase) && Password().IsMatch(line));
        }));
    }

    static IEnumerable<(string Section, string Value)> Passwords(string text)
    {
        string? current = null;
        foreach (var line in NpmRc.Lines(text))
        {
            if (Section().Match(line) is { Success: true } header)
                // A section name is printed inside a command to copy; one holding shell syntax is passed over.
                current = header.Groups["name"].Value.IndexOfAny(['"', '\'', '$', '`']) < 0 ? header.Groups["name"].Value : null;
            else if (current is not null && Password().Match(line) is { Success: true } password)
                yield return (current, password.Groups["value"].Value);
        }
    }

    [GeneratedRegex(@"^\[[ \t]*(?<name>[^\]\r\n]+?)[ \t]*\]")]
    private static partial Regex Section();

    [GeneratedRegex(@"^password[ \t]*[=:][ \t]*(?<value>[^\r\n]*?)[ \t]*\r?\n?$", RegexOptions.IgnoreCase)]
    private static partial Regex Password();
}
