using Tiresias.UserSecrets;

namespace Tiresias.App.Logic;

/// <summary>One user-secrets folder as the editor lists it.</summary>
/// <param name="Name">The project's name, or the id when no project is known to use it.</param>
/// <param name="Paths">Every project file known to use the id; empty when none is.</param>
public sealed record ProjectEntry(string Id, string Name, IReadOnlyList<string> Paths)
{
    public bool Known => Paths.Count > 0;
}

/// <summary>
/// The project files that use one id, summed up so a repository with many worktrees is one line:
/// the first file, how many copies of it (other checkouts: the same file name), and how many other projects.
/// </summary>
public sealed record ProjectPaths(string First, int Copies, int Others)
{
    /// <summary>The main checkout is usually the shortest path: worktrees nest under a longer one.</summary>
    public static ProjectPaths Of(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
            return new("", 0, 0);
        var first = paths.OrderBy(p => p.Length).ThenBy(p => p, StringComparer.OrdinalIgnoreCase).First();
        var name = Path.GetFileName(first);
        var copies = paths.Count(p => string.Equals(Path.GetFileName(p), name, StringComparison.OrdinalIgnoreCase)) - 1;
        return new(first, copies, paths.Count - 1 - copies);
    }

    /// <summary>Every file is a checkout of one project.</summary>
    public bool OnlyCheckouts => Copies > 0 && Others == 0;

    public int More => Copies + Others;
}

/// <summary>The editor's project list: named projects first, by name, then the ids no known project uses.</summary>
public static class ProjectList
{
    public static IReadOnlyList<ProjectEntry> Build(IEnumerable<string> ids, ProjectIndex index) =>
        ids.Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(id => Entry(id, index))
            .OrderBy(e => e.Known ? 0 : 1)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Id, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static ProjectEntry Entry(string id, ProjectIndex index)
    {
        var projects = index.For(id);
        return projects.Count == 0
            ? new(id, id, [])
            : new(id, Path.GetFileNameWithoutExtension(projects[0].Path), [.. projects.Select(p => p.Path)]);
    }

    /// <summary>
    /// Ids that may go to the Recycle Bin: no known project uses them, and at least one folder was
    /// scanned. With nothing scanned every id is unknown, which says nothing about whether it is used.
    /// </summary>
    public static IReadOnlyList<string> Unused(IEnumerable<ProjectEntry> entries, ProjectIndex index) =>
        index.Folders.Count == 0 ? [] : [.. entries.Where(e => !e.Known).Select(e => e.Id)];

    /// <summary>
    /// The picker's entries: within each group, folders holding secrets before settings-only ones.
    /// Empty folders are left out unless <paramref name="showEmpty"/>, or the id was opened by name
    /// (<paramref name="kept"/>), so a Review from Home never lands on nothing.
    /// </summary>
    public static IReadOnlyList<ProjectEntry> Listed(IEnumerable<ProjectEntry> entries, Func<string, SecretsContent> contentOf, ISet<string> kept, bool showEmpty) =>
        [.. entries
            .Select(e => (Entry: e, Content: contentOf(e.Id)))
            .Where(x => showEmpty || x.Content != SecretsContent.Empty || kept.Contains(x.Entry.Id))
            .OrderBy(x => x.Entry.Known ? 0 : 1)
            .ThenBy(x => x.Content switch { SecretsContent.Settings => 1, SecretsContent.Empty => 2, _ => 0 })
            .Select(x => x.Entry)];
}
