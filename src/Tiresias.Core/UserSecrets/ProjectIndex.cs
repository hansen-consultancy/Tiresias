namespace Tiresias.UserSecrets;

/// <summary>A project file that declares a <c>&lt;UserSecretsId&gt;</c>.</summary>
public sealed record ProjectFile(string Path, string Id);

/// <summary>
/// Which projects use which user-secrets id. A user-secrets folder is named after its id only, so
/// without this a list of folders is a list of GUIDs. Filled by scanning folders the user picked,
/// and by linking: the program that asked for an id, or a project the user pointed at.
/// </summary>
/// <param name="Folders">Folders the user asked to scan; rescanned whenever the secrets editor opens.</param>
/// <param name="Projects">Every project seen, scanned or linked.</param>
public sealed record ProjectIndex(IReadOnlyList<string> Folders, IReadOnlyList<ProjectFile> Projects)
{
    public static ProjectIndex Empty { get; } = new([], []);

    /// <summary>The projects using <paramref name="id"/>: several after a project was copied.</summary>
    public IReadOnlyList<ProjectFile> For(string id) =>
        Projects.Where(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => System.IO.Path.GetFileNameWithoutExtension(p.Path), StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public ProjectIndex WithFolder(string folder) =>
        Folders.Contains(folder, StringComparer.OrdinalIgnoreCase)
            ? this
            : this with { Folders = [.. Folders.Append(folder).Order(StringComparer.OrdinalIgnoreCase)] };

    /// <summary>Stops scanning <paramref name="folder"/>; the projects already found there stay until their files go.</summary>
    public ProjectIndex WithoutFolder(string folder) =>
        this with { Folders = [.. Folders.Where(f => !string.Equals(f, folder, StringComparison.OrdinalIgnoreCase))] };

    /// <summary>What a scan of <paramref name="folder"/> found replaces everything known under it, so a deleted or renamed project drops out.</summary>
    public ProjectIndex Rescanned(string folder, IEnumerable<ProjectFile> found) =>
        this with { Projects = Distinct(Projects.Where(p => !IsUnder(p.Path, folder)).Concat(found)) };

    /// <summary>Adds one project, or updates its id if the file changed.</summary>
    public ProjectIndex Linked(ProjectFile project) =>
        this with { Projects = Distinct(Projects.Where(p => !SamePath(p.Path, project.Path)).Append(project)) };

    /// <summary>
    /// Drops projects whose file is gone. One on a drive or share that isn't there right now stays:
    /// an unplugged disk is not a deleted project.
    /// </summary>
    public ProjectIndex Pruned(Func<string, bool> fileExists, Func<string, bool> rootAvailable) =>
        this with { Projects = [.. Projects.Where(p => fileExists(p.Path) || !rootAvailable(System.IO.Path.GetPathRoot(p.Path) ?? p.Path))] };

    public static bool IsUnder(string path, string folder)
    {
        var root = folder.TrimEnd('\\', '/');
        return path.Length > root.Length
            && path.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            && path[root.Length] is '\\' or '/';
    }

    static bool SamePath(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    static ProjectFile[] Distinct(IEnumerable<ProjectFile> projects) =>
        [.. projects.DistinctBy(p => p.Path, StringComparer.OrdinalIgnoreCase)];
}
