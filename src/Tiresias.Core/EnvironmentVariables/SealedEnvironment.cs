using System.Text.Json.Nodes;

namespace Tiresias.EnvironmentVariables;

/// <summary>Variables a folder adds to, or overrides in, the global set for commands run inside it. <paramref name="Folder"/> is a full path.</summary>
public sealed record FolderSet(string Folder, IReadOnlyList<SealedVariable> Variables);

/// <summary>A NuGet package source that authenticates with a sealed variable as its password. <paramref name="Source"/> is an https URL.</summary>
public sealed record NuGetSource(string Source, string Variable, string Username);

/// <summary>
/// A variable delivered as a broker placeholder instead of its value: the process gets a
/// <c>tirph_</c> placeholder in <paramref name="Variable"/> and the forwarder's URL for
/// <paramref name="Service"/> (a vault service, which holds the real key) in
/// <paramref name="BaseUrlVariable"/>.
/// </summary>
public sealed record EnvironmentPlaceholder(string Variable, string Service, string BaseUrlVariable);

/// <summary>
/// Everything sealed: one global set, plus folder sets kept in the store rather than in the folder,
/// so nothing can be committed to a repository by mistake. <see cref="Resolve"/> gives the variables
/// for a working directory: the global set, overlaid by each folder set from the drive root down,
/// the nearest folder winning. Folder paths compare as Windows does, ignoring case and treating
/// <c>\</c> and <c>/</c> alike. NuGet sources are sealed with the rest, so nobody can point a feed of
/// theirs at your token by editing a file. So are placeholder deliveries, keyed by variable name
/// wherever that name resolves, so nothing can quietly switch one back to the real value.
/// </summary>
public sealed record SealedEnvironment(IReadOnlyList<SealedVariable> Global, IReadOnlyList<FolderSet> Folders, IReadOnlyList<NuGetSource> NuGetSources,
    IReadOnlyList<EnvironmentPlaceholder> Placeholders)
{
    public static readonly SealedEnvironment Empty = new([], [], [], []);

    /// <summary>Azure Artifacts, GitHub Packages and most token feeds accept any user name with a token as the password.</summary>
    public const string NuGetDefaultUsername = "tiresias";

    public bool IsEmpty => Global.Count == 0 && Folders.All(f => f.Variables.Count == 0);

    /// <summary>The variables for a command run in <paramref name="directory"/>.</summary>
    public IReadOnlyList<SealedVariable> Resolve(string directory)
    {
        var here = Normalize(directory);
        return SealedVariables.With(Global, Folders
            .Where(f => Contains(Normalize(f.Folder), here))
            .OrderBy(f => Normalize(f.Folder).Length)
            .SelectMany(f => f.Variables));
    }

    /// <summary>The global set with <paramref name="added"/> replacing any of the same name.</summary>
    public SealedEnvironment WithGlobal(IEnumerable<SealedVariable> added) => this with { Global = SealedVariables.With(Global, added) };

    public SealedEnvironment WithoutGlobal(IEnumerable<string> names) => this with { Global = SealedVariables.Without(Global, names) };

    /// <summary><paramref name="folder"/>'s set with <paramref name="added"/> replacing any of the same name; the set is created when new.</summary>
    public SealedEnvironment WithFolder(string folder, IEnumerable<SealedVariable> added)
    {
        var existing = Find(folder);
        var set = new FolderSet(existing?.Folder ?? Trim(folder), SealedVariables.With(existing?.Variables ?? [], added));
        return this with { Folders = [.. Folders.Where(f => f != existing), set] };
    }

    /// <summary><paramref name="folder"/>'s set without <paramref name="names"/>; a set left empty is dropped.</summary>
    public SealedEnvironment WithoutFolder(string folder, IEnumerable<string> names)
    {
        if (Find(folder) is not { } existing)
            return this;
        var left = SealedVariables.Without(existing.Variables, names);
        return this with { Folders = [.. Folders.Where(f => f != existing).Concat(left.Count > 0 ? [existing with { Variables = left }] : [])] };
    }

    /// <summary><paramref name="source"/> replacing any mapping for the same URL.</summary>
    public SealedEnvironment WithNuGetSource(NuGetSource source) =>
        this with { NuGetSources = [.. NuGetSources.Where(s => !SameSource(s.Source, source.Source)), source] };

    public SealedEnvironment WithoutNuGetSource(string source) =>
        this with { NuGetSources = [.. NuGetSources.Where(s => !SameSource(s.Source, source))] };

    /// <summary>
    /// The mapping NuGet's request for <paramref name="uri"/> falls under: the source itself, or a
    /// URL under the folder its service index is in (where feeds serve packages). Https only, same
    /// host, so a mapping never answers for another server.
    /// </summary>
    public NuGetSource? NuGetSourceFor(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttps)
            return null;
        var asked = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        return NuGetSources
            .Where(s => Uri.TryCreate(s.Source, UriKind.Absolute, out var source) && source.Scheme == Uri.UriSchemeHttps
                && string.Equals(source.Host, uri.Host, StringComparison.OrdinalIgnoreCase) && source.Port == uri.Port)
            .Where(s => SameSource(s.Source, asked) || asked.StartsWith(Base(s.Source) + "/", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(s => s.Source.Length)
            .FirstOrDefault();
    }

    static bool SameSource(string a, string b) => string.Equals(a.TrimEnd('/'), b.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

    /// <summary>The folder a service index (<c>.../index.json</c>) is in; a source not ending in <c>.json</c> is its own folder.</summary>
    static string Base(string source)
    {
        var trimmed = source.TrimEnd('/');
        return trimmed.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? trimmed[..trimmed.LastIndexOf('/', StringComparison.Ordinal)] : trimmed;
    }

    /// <summary><paramref name="placeholder"/> replacing any delivery for the same variable.</summary>
    public SealedEnvironment WithPlaceholder(EnvironmentPlaceholder placeholder) =>
        this with { Placeholders = [.. Placeholders.Where(p => !SameName(p.Variable, placeholder.Variable)), placeholder] };

    public SealedEnvironment WithoutPlaceholder(string variable) =>
        this with { Placeholders = [.. Placeholders.Where(p => !SameName(p.Variable, variable))] };

    /// <summary>How <paramref name="variable"/> is delivered as a placeholder, or <c>null</c> when it gets its value.</summary>
    public EnvironmentPlaceholder? PlaceholderFor(string variable) => Placeholders.FirstOrDefault(p => SameName(p.Variable, variable));

    /// <summary>
    /// Whether <paramref name="name"/> is sealed anywhere: globally or in a folder set.
    /// </summary>
    public bool IsSealedAnywhere(string name) =>
        Global.Concat(Folders.SelectMany(f => f.Variables)).Any(v => SameName(v.Name, name));

    /// <summary>
    /// The base-URL variable tools conventionally pair with an API key variable:
    /// <c>OPENAI_API_KEY</c> → <c>OPENAI_BASE_URL</c>. <c>null</c> when the name doesn't end in
    /// <c>_API_KEY</c>, <c>_KEY</c> or <c>_TOKEN</c>, or nothing is left in front of it.
    /// </summary>
    public static string? BaseUrlVariableFor(string variable)
    {
        foreach (var suffix in (string[])["_API_KEY", "_KEY", "_TOKEN"])
            if (variable.Length > suffix.Length && variable.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return variable[..^suffix.Length].ToUpperInvariant() + "_BASE_URL";
        return null;
    }

    static bool SameName(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    public FolderSet? Find(string folder) => Folders.FirstOrDefault(f => Normalize(f.Folder) == Normalize(folder));

    /// <summary>The document this is sealed as. A phase-1 document, with only the global set, reads unchanged.</summary>
    public JsonObject ToDocument()
    {
        var document = SealedVariables.ToDocument(Global);
        var folders = new JsonObject();
        foreach (var set in Folders.Where(f => f.Variables.Count > 0))
            folders[set.Folder] = SealedVariables.ToDocument(set.Variables);
        if (folders.Count > 0)
            document["folders"] = folders;
        var nuget = new JsonObject();
        foreach (var source in NuGetSources)
            nuget[source.Source] = new JsonObject { ["variable"] = source.Variable, ["username"] = source.Username };
        if (nuget.Count > 0)
            document["nuget"] = nuget;
        var placeholders = new JsonObject();
        foreach (var placeholder in Placeholders)
            placeholders[placeholder.Variable] = new JsonObject { ["service"] = placeholder.Service, ["baseUrl"] = placeholder.BaseUrlVariable };
        if (placeholders.Count > 0)
            document["placeholders"] = placeholders;
        return document;
    }

    /// <exception cref="InvalidDataException">The document is not one <see cref="ToDocument"/> wrote.</exception>
    public static SealedEnvironment FromDocument(JsonObject document)
    {
        if (document.Count == 0)
            return Empty;
        var folders = document["folders"] switch
        {
            null => [],
            JsonObject sets => sets.Select(pair => new FolderSet(pair.Key,
                SealedVariables.FromDocument(pair.Value as JsonObject ?? throw new InvalidDataException($"The sealed folder set {pair.Key} is not an object.")))).ToArray(),
            _ => throw new InvalidDataException("The sealed folder sets are not an object."),
        };
        var nuget = document["nuget"] switch
        {
            null => [],
            JsonObject sources => sources.Select(pair => pair.Value is JsonObject map && (string?)map["variable"] is { } variable
                ? new NuGetSource(pair.Key, variable, (string?)map["username"] ?? NuGetDefaultUsername)
                : throw new InvalidDataException($"The sealed NuGet source {pair.Key} names no variable.")).ToArray(),
            _ => throw new InvalidDataException("The sealed NuGet sources are not an object."),
        };
        var placeholders = document["placeholders"] switch
        {
            null => [],
            JsonObject deliveries => deliveries.Select(pair => pair.Value is JsonObject map && (string?)map["service"] is { } service && (string?)map["baseUrl"] is { } baseUrl
                ? new EnvironmentPlaceholder(pair.Key, service, baseUrl)
                : throw new InvalidDataException($"The placeholder delivery for {pair.Key} names no service or base-URL variable.")).ToArray(),
            _ => throw new InvalidDataException("The sealed placeholder deliveries are not an object."),
        };
        return new(SealedVariables.FromDocument(document), folders, nuget, placeholders);
    }

    static bool Contains(string folder, string directory) =>
        directory == folder || directory.StartsWith(folder.EndsWith('/', StringComparison.Ordinal) || folder.EndsWith(':', StringComparison.Ordinal) ? folder : folder + "/", StringComparison.Ordinal);

    static string Normalize(string path) => Trim(path).Replace('\\', '/').ToUpperInvariant();

    static string Trim(string path) => path.Length > 1 ? path.TrimEnd('\\', '/') : path;
}
