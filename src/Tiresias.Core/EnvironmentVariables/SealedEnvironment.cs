using System.Text.Json.Nodes;

namespace Tiresias.EnvironmentVariables;

/// <summary>Variables a folder adds to, or overrides in, the global set for commands run inside it. <paramref name="Folder"/> is a full path.</summary>
public sealed record FolderSet(string Folder, IReadOnlyList<SealedVariable> Variables);

/// <summary>A NuGet package source that authenticates with a sealed variable as its password. <paramref name="Source"/> is an https URL.</summary>
public sealed record NuGetSource(string Source, string Variable, string Username)
{
    public const string UrlRequirement = "Use an HTTPS feed URL without user information, a query string or a fragment";

    public static Uri? ParseUrl(string? source) =>
        Uri.TryCreate(source, UriKind.Absolute, out var uri) && IsSupported(uri) ? uri : null;

    internal static bool IsSupported(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps
        && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;
}

/// <summary>
/// A git host whose HTTPS remotes authenticate with a sealed variable as the password, for
/// <c>tir-remote git-credential</c> in a devcontainer. <paramref name="Host"/> is what git's credential
/// protocol sends: the host name, lower case, with <c>:port</c> when it isn't 443.
/// </summary>
public sealed record GitHost(string Host, string Variable, string Username)
{
    public const string HostRequirement = "Use a host name such as github.com, with :port only when it isn't 443; no scheme, user or path";

    /// <summary>GitHub, GitLab, Azure Repos and Bitbucket take any user name with a token as the password.</summary>
    public const string DefaultUsername = "tiresias";

    /// <summary>The host as git sends it, or <c>null</c> when <paramref name="host"/> isn't just a host and port.</summary>
    public static string? Normalize(string? host) =>
        host is { Length: > 0 } && !host.Contains('/', StringComparison.Ordinal) && !host.Contains('@', StringComparison.Ordinal)
            && Uri.TryCreate($"https://{host}/", UriKind.Absolute, out var uri) && uri.AbsolutePath == "/" && uri.Query.Length == 0 && uri.Fragment.Length == 0
            ? (uri.IsDefaultPort ? uri.IdnHost : $"{uri.IdnHost}:{uri.Port}").ToLowerInvariant()
            : null;
}

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
/// <see cref="Configuration"/> names the variables a .NET app may ask for itself, through
/// <c>Tiresias.Extensions.Configuration</c>, when nothing started it with them: a delivery beside
/// value and placeholder, never both a placeholder and this.
/// </summary>
public sealed record SealedEnvironment(IReadOnlyList<SealedVariable> Global, IReadOnlyList<FolderSet> Folders, IReadOnlyList<NuGetSource> NuGetSources,
    IReadOnlyList<EnvironmentPlaceholder> Placeholders)
{
    public static readonly SealedEnvironment Empty = new([], [], [], []);

    /// <summary>The variables marked for configuration delivery, by name wherever that name resolves.</summary>
    public IReadOnlyList<string> Configuration { get; init; } = [];

    /// <summary>Git hosts a devcontainer's credential helper may ask a token for, sealed so no file can point one elsewhere.</summary>
    public IReadOnlyList<GitHost> GitHosts { get; init; } = [];

    /// <summary>Azure Artifacts, GitHub Packages and most token feeds accept any user name with a token as the password.</summary>
    public const string NuGetDefaultUsername = "tiresias";

    public bool IsEmpty => Global.Count == 0 && Folders.All(f => f.Variables.Count == 0);

    /// <summary>The variables for a command run in <paramref name="directory"/>.</summary>
    public IReadOnlyList<SealedVariable> Resolve(string directory) => [.. ResolveWithFolders(directory).Select(v => v.Variable)];

    /// <summary>The same overlay with each variable's origin, so terminal approval can distinguish a folder override from a global value.</summary>
    public IReadOnlyList<(SealedVariable Variable, string? Folder)> ResolveWithFolders(string directory)
    {
        var here = Normalize(directory);
        var scoped = Folders
            .Where(f => Contains(Normalize(f.Folder), here))
            .OrderBy(f => Normalize(f.Folder).Length)
            .SelectMany(f => f.Variables.Select(v => (Variable: v, Folder: (string?)f.Folder)));
        return [.. Global.Select(v => (Variable: v, Folder: (string?)null)).Concat(scoped)
            .GroupBy(v => v.Variable.Name, StringComparer.OrdinalIgnoreCase).Select(group => group.Last())];
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
    public SealedEnvironment WithNuGetSource(NuGetSource source)
    {
        if (NuGetSource.ParseUrl(source.Source) is null)
            throw new ArgumentException(NuGetSource.UrlRequirement, nameof(source));
        return this with { NuGetSources = [.. NuGetSources.Where(s => !SameSource(s.Source, source.Source)), source] };
    }

    public SealedEnvironment WithoutNuGetSource(string source) =>
        this with { NuGetSources = [.. NuGetSources.Where(s => !SameSource(s.Source, source))] };

    /// <summary>
    /// NuGet asks its credential provider for the configured package source. Other endpoints,
    /// including package URLs published by the service index, do not identify that source.
    /// </summary>
    public NuGetSource? NuGetSourceFor(Uri uri)
    {
        if (!NuGetSource.IsSupported(uri))
            return null;
        NuGetSource? match = null;
        foreach (var mapping in NuGetSources)
        {
            if (NuGetSource.ParseUrl(mapping.Source) is not { } source || !SameEndpoint(source, uri))
                continue;
            if (match is not null)
                return null;
            match = mapping;
        }
        return match;
    }

    static bool SameSource(string a, string b) => a == b ||
        (NuGetSource.ParseUrl(a) is { } left && NuGetSource.ParseUrl(b) is { } right && SameEndpoint(left, right));

    static bool SameEndpoint(Uri left, Uri right) => left.Port == right.Port && left.AbsolutePath == right.AbsolutePath
        && string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase);

    /// <exception cref="ArgumentException">The host isn't one <see cref="GitHost.Normalize"/> takes.</exception>
    public SealedEnvironment WithGitHost(GitHost host) =>
        GitHost.Normalize(host.Host) is not { } normalized
            ? throw new ArgumentException(GitHost.HostRequirement, nameof(host))
            : this with { GitHosts = [.. GitHosts.Where(h => h.Host != normalized), host with { Host = normalized }] };

    public SealedEnvironment WithoutGitHost(string host) =>
        this with { GitHosts = [.. GitHosts.Where(h => h.Host != (GitHost.Normalize(host) ?? host))] };

    /// <summary>The mapping for the host git asks about over HTTPS; <c>null</c> for another protocol or an unmapped host.</summary>
    public GitHost? GitHostFor(string? protocol, string? host) =>
        protocol == "https" && GitHost.Normalize(host) is { } normalized ? GitHosts.FirstOrDefault(h => h.Host == normalized) : null;

    /// <summary><paramref name="placeholder"/> replacing any delivery for the same variable.</summary>
    /// <exception cref="InvalidOperationException">The variable is marked for configuration: a .NET app would get the placeholder in place of its value.</exception>
    public SealedEnvironment WithPlaceholder(EnvironmentPlaceholder placeholder) =>
        IsForConfiguration(placeholder.Variable)
            ? throw new InvalidOperationException($"{placeholder.Variable} is handed to .NET apps as its value; unmark it for configuration first.")
            : this with { Placeholders = [.. Placeholders.Where(p => !SameName(p.Variable, placeholder.Variable)), placeholder] };

    /// <summary>Marks <paramref name="variable"/> for configuration delivery; marking it twice changes nothing.</summary>
    /// <exception cref="InvalidOperationException">It is delivered as a placeholder, which a .NET app's configuration can't use.</exception>
    public SealedEnvironment WithConfiguration(string variable) =>
        PlaceholderFor(variable) is not null
            ? throw new InvalidOperationException($"{variable} is handed out as a placeholder; switch it back to its value first.")
            : IsForConfiguration(variable) ? this : this with { Configuration = [.. Configuration, variable] };

    public SealedEnvironment WithoutConfiguration(string variable) =>
        this with { Configuration = [.. Configuration.Where(name => !SameName(name, variable))] };

    public bool IsForConfiguration(string variable) => Configuration.Any(name => SameName(name, variable));

    /// <summary>
    /// What a .NET app in <paramref name="directory"/> may ask for: the variables resolved there that
    /// are marked for configuration, less those it already has (<paramref name="present"/>), so a
    /// process started by <c>tir run</c> or a terminal is not asked again. Each comes with its origin,
    /// for consent.
    /// </summary>
    public IReadOnlyList<(SealedVariable Variable, string? Folder)> ForConfiguration(string directory, IEnumerable<string> present)
    {
        var have = present.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. ResolveWithFolders(directory).Where(v => IsForConfiguration(v.Variable.Name) && !have.Contains(v.Variable.Name)
            && PlaceholderFor(v.Variable.Name) is null)];
    }

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
        var git = new JsonObject();
        foreach (var host in GitHosts)
            git[host.Host] = new JsonObject { ["variable"] = host.Variable, ["username"] = host.Username };
        if (git.Count > 0)
            document["git"] = git;
        if (Configuration.Count > 0)
            document["configuration"] = new JsonArray([.. Configuration.Select(name => (JsonNode)name)]);
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
        var configuration = document["configuration"] switch
        {
            null => [],
            JsonArray names => names.Select(name => name?.GetValueKind() == System.Text.Json.JsonValueKind.String
                ? (string)name! : throw new InvalidDataException("A name marked for configuration is not a string.")).ToArray(),
            _ => throw new InvalidDataException("The names marked for configuration are not an array."),
        };
        var git = document["git"] switch
        {
            null => [],
            JsonObject hosts => hosts.Select(pair => pair.Value is JsonObject map && (string?)map["variable"] is { } variable
                ? new GitHost(pair.Key, variable, (string?)map["username"] ?? GitHost.DefaultUsername)
                : throw new InvalidDataException($"The sealed git host {pair.Key} names no variable.")).ToArray(),
            _ => throw new InvalidDataException("The sealed git hosts are not an object."),
        };
        return new(SealedVariables.FromDocument(document), folders, nuget, placeholders) { Configuration = configuration, GitHosts = git };
    }

    static bool Contains(string folder, string directory) =>
        directory == folder || directory.StartsWith(folder.EndsWith('/', StringComparison.Ordinal) || folder.EndsWith(':', StringComparison.Ordinal) ? folder : folder + "/", StringComparison.Ordinal);

    internal static string Normalize(string path) => Trim(path).Replace('\\', '/').ToUpperInvariant();

    static string Trim(string path) => path.Length > 1 ? path.TrimEnd('\\', '/') : path;
}
