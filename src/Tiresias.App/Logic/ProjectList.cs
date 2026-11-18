using Tiresias.UserSecrets;

namespace Tiresias.App.Logic;

/// <summary>One user-secrets folder as the editor lists it.</summary>
/// <param name="Name">The project's name, or the id when no project is known to use it.</param>
/// <param name="Paths">Every project file known to use the id; empty when none is.</param>
public sealed record ProjectEntry(string Id, string Name, IReadOnlyList<string> Paths)
{
    public bool Known => Paths.Count > 0;
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
}
