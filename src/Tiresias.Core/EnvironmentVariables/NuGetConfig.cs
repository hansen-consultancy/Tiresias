using System.Xml;
using System.Xml.Linq;

namespace Tiresias.EnvironmentVariables;

/// <summary>How a NuGet.Config entry holds a source's password.</summary>
public enum NuGetPasswordKind
{
    /// <summary><c>ClearTextPassword</c> is exactly <c>%NAME%</c>: an environment variable.</summary>
    Variable,

    /// <summary><c>ClearTextPassword</c> is the token itself, in plain text on disk.</summary>
    ClearText,

    /// <summary><c>Password</c>, encrypted by NuGet with the Windows account.</summary>
    Encrypted,
}

/// <summary>
/// One source's credentials as a NuGet.Config file has them. <paramref name="Source"/> is null when
/// the file has credentials for a source it doesn't define (another config file does);
/// <paramref name="Password"/> is the variable's name for <see cref="NuGetPasswordKind.Variable"/>,
/// the token for <see cref="NuGetPasswordKind.ClearText"/>, and null when encrypted.
/// </summary>
public sealed record NuGetConfigCredential(string Key, string? Source, string? Username, NuGetPasswordKind Kind, string? Password)
{
    /// <summary>The variable named by the user name, when it is exactly <c>%NAME%</c>.</summary>
    public string? UsernameVariable => NuGetConfig.VariableIn(Username);
}

/// <summary>
/// Finds the credentials NuGet.Config files hold for package sources, and takes them out once the
/// sources are mapped to sealed variables. NuGet only asks its credential plugins when the config
/// has no credentials for a source, so leaving them in would bypass Tiresias.
/// </summary>
public static class NuGetConfig
{
    /// <summary>
    /// The config files NuGet reads for <paramref name="directory"/>, nearest first: a
    /// <c>nuget.config</c> in it or any parent, then the user's own. Only those that exist; the
    /// user's own alone when <paramref name="directory"/> is null.
    /// </summary>
    public static IReadOnlyList<string> Files(string? directory, string appData)
    {
        var files = new List<string>();
        for (var at = directory is null ? null : new DirectoryInfo(directory); at is not null; at = at.Parent)
        {
            var file = Path.Combine(at.FullName, "nuget.config");
            if (File.Exists(file))
                files.Add(file);
        }
        var user = Path.Combine(appData, "NuGet");
        if (File.Exists(Path.Combine(user, "NuGet.Config")))
            files.Add(Path.Combine(user, "NuGet.Config"));
        if (Directory.Exists(Path.Combine(user, "config")))
            files.AddRange(Directory.GetFiles(Path.Combine(user, "config"), "*.config").Order(StringComparer.OrdinalIgnoreCase));
        return files;
    }

    /// <summary>Every source with credentials in <paramref name="xml"/>; none when it isn't a NuGet.Config.</summary>
    public static IReadOnlyList<NuGetConfigCredential> Read(string xml)
    {
        if (Parse(xml, LoadOptions.None)?.Root is not { } root)
            return [];
        var sources = root.Element("packageSources")?.Elements("add")
            .Where(e => e.Attribute("key") is not null && e.Attribute("value") is not null)
            .GroupBy(e => (string)e.Attribute("key")!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (string)g.Last().Attribute("value")!, StringComparer.OrdinalIgnoreCase) ?? [];

        return [.. (root.Element("packageSourceCredentials")?.Elements() ?? []).Select(element =>
        {
            var key = XmlConvert.DecodeName(element.Name.LocalName);
            string? Value(string name) => element.Elements("add")
                .LastOrDefault(e => string.Equals((string?)e.Attribute("key"), name, StringComparison.OrdinalIgnoreCase))?.Attribute("value")?.Value;
            var clearText = Value("ClearTextPassword");
            var (kind, password) = clearText is null ? (NuGetPasswordKind.Encrypted, (string?)null)
                : VariableIn(clearText) is { } variable ? (NuGetPasswordKind.Variable, variable)
                : (NuGetPasswordKind.ClearText, clearText);
            return clearText is null && Value("Password") is null
                ? null
                : new NuGetConfigCredential(key, sources.GetValueOrDefault(key), Value("Username"), kind, password);
        }).OfType<NuGetConfigCredential>()];
    }

    /// <summary>The sources with a push key under <c>apikeys</c>, which NuGet encrypts for the Windows account. Never the keys.</summary>
    public static IReadOnlyList<string> ApiKeySources(string xml) =>
        [.. Parse(xml, LoadOptions.None)?.Root?.Element("apikeys")?.Elements("add")
            .Where(e => !string.IsNullOrEmpty((string?)e.Attribute("value")))
            .Select(e => (string?)e.Attribute("key")).OfType<string>() ?? []];

    /// <summary>
    /// <paramref name="xml"/> without the credentials for <paramref name="keys"/>, and without an
    /// emptied <c>packageSourceCredentials</c>. Everything else, layout included, stays as it was.
    /// </summary>
    public static string WithoutCredentials(string xml, IEnumerable<string> keys)
    {
        var document = Parse(xml, LoadOptions.PreserveWhitespace) ?? throw new InvalidDataException("Not a NuGet.Config file.");
        var removing = keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (document.Root?.Element("packageSourceCredentials") is not { } credentials)
            return xml;
        foreach (var element in credentials.Elements().Where(e => removing.Contains(XmlConvert.DecodeName(e.Name.LocalName))).ToArray())
            RemoveWithLine(element);
        if (!credentials.Elements().Any())
            RemoveWithLine(credentials);

        // The parser reads every line ending as \n; written back as the file had them, not as this OS does.
        var root = new System.Text.StringBuilder();
        using (var writer = XmlWriter.Create(root, new() { OmitXmlDeclaration = true, NewLineHandling = NewLineHandling.None }))
            document.Root.Save(writer);
        var body = xml.Contains("\r\n", StringComparison.Ordinal) ? root.ToString().ReplaceLineEndings("\r\n") : root.ToString();
        // What surrounds the root (declaration, comments, the final newline) is kept as it was written.
        var start = xml.IndexOf("<configuration", StringComparison.Ordinal);
        return xml[..start] + body + xml[xml.TrimEnd().Length..];
    }

    /// <summary>The variable's name when <paramref name="value"/> is exactly <c>%NAME%</c>.</summary>
    public static string? VariableIn(string? value) =>
        value is { Length: > 2 } && value[0] == '%' && value[^1] == '%' && !value.AsSpan(1, value.Length - 2).Contains('%')
            ? value[1..^1]
            : null;

    /// <summary>A name to seal a plain-text token under: <c>NUGET_</c> and the source key, upper case, letters and digits only.</summary>
    public static string VariableNameFor(string key) =>
        "NUGET_" + new string([.. key.ToUpperInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_')]).Trim('_') + "_TOKEN";

    static XDocument? Parse(string xml, LoadOptions options)
    {
        try
        {
            var document = XDocument.Parse(xml, options);
            return document.Root?.Name.LocalName == "configuration" ? document : null;
        }
        catch (XmlException)
        {
            return null;
        }
    }

    /// <summary>Removes the element and the indentation before it, so no blank line is left behind.</summary>
    static void RemoveWithLine(XElement element)
    {
        if (element.PreviousNode is XText { Value: var space } before && string.IsNullOrWhiteSpace(space))
            before.Remove();
        element.Remove();
    }
}

/// <summary>
/// What <c>tir env nuget import</c> does with one source's credentials from one config file:
/// map <paramref name="Source"/> to <paramref name="Variable"/>, sealing it first from Windows
/// (<paramref name="ProtectFirst"/>) or from the file's plain text (<paramref name="SealClearText"/>),
/// then take the credentials out of <paramref name="File"/>. <paramref name="Skip"/> says why not.
/// </summary>
public sealed record NuGetImportStep(string File, NuGetConfigCredential Credential, string? Variable, string Username,
    bool ProtectFirst = false, bool SealClearText = false, string? Skip = null)
{
    public bool Acts => Skip is null;
}

public static class NuGetImport
{
    /// <summary>
    /// The steps for every credential found, in order. <paramref name="inWindows"/> says whether a
    /// user environment variable exists; <paramref name="valueOf"/> gives a user name variable's
    /// value, sealed or from Windows, so the mapping holds the name itself.
    /// </summary>
    public static IReadOnlyList<NuGetImportStep> Plan(IEnumerable<(string File, NuGetConfigCredential Credential)> found,
        SealedEnvironment sealedNow, Func<string, bool> inWindows, Func<string, string?> valueOf)
    {
        bool SealedGlobally(string name) => sealedNow.Global.Any(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase));
        return [.. found.Select(f =>
        {
            var c = f.Credential;
            var username = c.UsernameVariable is { } userVariable ? valueOf(userVariable) ?? SealedEnvironment.NuGetDefaultUsername
                : c.Username is { Length: > 0 } literal ? literal : SealedEnvironment.NuGetDefaultUsername;
            NuGetImportStep Skip(string why) => new(f.File, c, null, username, Skip: why);

            if (c.Source is null)
                return Skip("its source is defined in another config file; run this where that one applies");
            if (!Uri.TryCreate(c.Source, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                return Skip("not an https source");
            switch (c.Kind)
            {
                case NuGetPasswordKind.Encrypted:
                    return Skip("encrypted by NuGet, so tir can't read it; seal the token with tir env set <NAME>, then tir env nuget add");
                case NuGetPasswordKind.Variable when SealedGlobally(c.Password!):
                    return new(f.File, c, c.Password, username);
                case NuGetPasswordKind.Variable when inWindows(c.Password!):
                    return new(f.File, c, c.Password, username, ProtectFirst: true);
                case NuGetPasswordKind.Variable when sealedNow.IsSealedAnywhere(c.Password!):
                    return Skip($"{c.Password} is sealed for a folder only; NuGet needs it in the global set (tir env set {c.Password})");
                case NuGetPasswordKind.Variable:
                    return Skip($"{c.Password} isn't set, in Windows or sealed");
                default:
                    var name = NuGetConfig.VariableNameFor(c.Key);
                    return SealedGlobally(name) || inWindows(name)
                        ? Skip($"the token is in plain text, but {name} is taken; seal it under another name with tir env set, then tir env nuget add")
                        : new(f.File, c, name, username, SealClearText: true);
            }
        })];
    }
}
