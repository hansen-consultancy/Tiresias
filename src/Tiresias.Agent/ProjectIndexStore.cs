using System.Text.Json;
using Tiresias.UserSecrets;

namespace Tiresias.Agent;

/// <summary>
/// The <see cref="ProjectIndex"/> on disk (<c>projects.json</c> beside the keyring). The agent links
/// from its pipe while the editor scans, so every change goes through <see cref="Update"/>.
/// Holds paths and ids only, never a value.
/// </summary>
public static class ProjectIndexStore
{
    static readonly Lock gate = new();

    static string FilePath => Path.Combine(KeyringStore.Directory, "projects.json");

    /// <summary>The index, or an empty one when there is none or it is damaged: it is rebuilt by the next scan.</summary>
    public static ProjectIndex Load()
    {
        lock (gate)
            return Read();
    }

    public static ProjectIndex Update(Func<ProjectIndex, ProjectIndex> change)
    {
        lock (gate)
        {
            var before = Read();
            var after = change(before);
            if (after != before)
            {
                Directory.CreateDirectory(KeyringStore.Directory);
                var temp = FilePath + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(after, JsonSerializerOptions.Web));
                File.Move(temp, FilePath, overwrite: true);
            }
            return after;
        }
    }

    /// <summary>Rescans every remembered folder that is there now, then drops projects whose file is gone.</summary>
    public static ProjectIndex Rescan(CancellationToken ct = default)
    {
        var folders = Load().Folders;
        var scans = folders.Where(Directory.Exists).Select(f => (Folder: f, Found: ProjectScanner.Scan(f, ct))).ToArray();
        return Update(index =>
        {
            foreach (var (folder, found) in scans)
                index = index.Rescanned(folder, found);
            return index.Pruned(File.Exists, Directory.Exists);
        });
    }

    /// <summary>
    /// Links an id to the project the asking program was built from (<c>dotnet run</c>, the debugger).
    /// Best effort and quiet: a program not built from a project here links nothing.
    /// </summary>
    public static void LinkFromCaller(string? caller, string id)
    {
        if (caller is null || !Path.IsPathFullyQualified(caller))
            return;
        try
        {
            if (ProjectScanner.FromExecutable(caller, id) is { } project && !Load().Projects.Contains(project))
                Update(index => index.Linked(project));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The index can't be written right now; the next request tries again.
        }
    }

    static ProjectIndex Read()
    {
        try
        {
            return File.Exists(FilePath)
                ? Normalised(JsonSerializer.Deserialize<ProjectIndex>(File.ReadAllText(FilePath), JsonSerializerOptions.Web))
                : ProjectIndex.Empty;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return ProjectIndex.Empty;
        }
    }

    /// <summary>A hand-edited or truncated file can leave a list out.</summary>
    static ProjectIndex Normalised(ProjectIndex? index) =>
        index is null ? ProjectIndex.Empty : new(index.Folders ?? [], index.Projects ?? []);
}
