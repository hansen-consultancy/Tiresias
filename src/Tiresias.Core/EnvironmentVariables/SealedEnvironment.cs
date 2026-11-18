using System.Text.Json.Nodes;

namespace Tiresias.EnvironmentVariables;

/// <summary>Variables a folder adds to, or overrides in, the global set for commands run inside it. <paramref name="Folder"/> is a full path.</summary>
public sealed record FolderSet(string Folder, IReadOnlyList<SealedVariable> Variables);

/// <summary>
/// Everything sealed: one global set, plus folder sets kept in the store rather than in the folder,
/// so nothing can be committed to a repository by mistake. <see cref="Resolve"/> gives the variables
/// for a working directory: the global set, overlaid by each folder set from the drive root down,
/// the nearest folder winning. Folder paths compare as Windows does, ignoring case and treating
/// <c>\</c> and <c>/</c> alike.
/// </summary>
public sealed record SealedEnvironment(IReadOnlyList<SealedVariable> Global, IReadOnlyList<FolderSet> Folders)
{
    public static readonly SealedEnvironment Empty = new([], []);

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
        return new(SealedVariables.FromDocument(document), folders);
    }

    static bool Contains(string folder, string directory) =>
        directory == folder || directory.StartsWith(folder.EndsWith('/') || folder.EndsWith(':') ? folder : folder + "/", StringComparison.Ordinal);

    static string Normalize(string path) => Trim(path).Replace('\\', '/').ToUpperInvariant();

    static string Trim(string path) => path.Length > 1 ? path.TrimEnd('\\', '/') : path;
}
