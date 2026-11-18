using System.Text.RegularExpressions;

namespace Tiresias.UserSecrets;

/// <summary>Finds project files and the user-secrets id each declares. Reads project files only; never a secret.</summary>
public static partial class ProjectScanner
{
    /// <summary>Build output, packages and tool folders: large, and never the home of a project someone edits.</summary>
    static readonly HashSet<string> Skipped = new(StringComparer.OrdinalIgnoreCase)
    {
        "bin", "obj", "node_modules", ".git", ".vs", ".idea", "packages", "TestResults",
    };

    static readonly string[] Extensions = [".csproj", ".fsproj", ".vbproj"];

    /// <summary>A project file larger than this is not hand-written: skipped rather than read.</summary>
    const long MaxProjectBytes = 1024 * 1024;

    // Junctions and symbolic links are skipped, so a link back up the tree can't loop the scan.
    static readonly EnumerationOptions Options = new()
    {
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System,
    };

    /// <summary>Every project under <paramref name="folder"/> that declares a user-secrets id. Folders it can't read are passed over.</summary>
    public static IReadOnlyList<ProjectFile> Scan(string folder, CancellationToken ct = default)
    {
        var found = new List<ProjectFile>();
        var pending = new Stack<string>();
        pending.Push(Path.GetFullPath(folder));
        while (pending.TryPop(out var dir))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*proj", Options))
                    if (IsProject(file) && IdOf(file) is { } id)
                        found.Add(new(file, id));
                foreach (var sub in Directory.EnumerateDirectories(dir, "*", Options))
                    if (!Skipped.Contains(Path.GetFileName(sub)))
                        pending.Push(sub);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Gone or locked meanwhile: the rest of the tree is still worth scanning.
            }
        }
        return found;
    }

    /// <summary>
    /// The project an executable was built from, if it declares <paramref name="id"/>: the folders above
    /// <c>bin\Debug\net10.0\App.exe</c> are searched for it. <c>null</c> for <c>dotnet.exe</c> running a
    /// dll, a published copy, or anything that doesn't match.
    /// </summary>
    public static ProjectFile? FromExecutable(string executable, string id, int levels = 6)
    {
        var dir = Path.GetDirectoryName(executable);
        for (var i = 0; i < levels && dir is not null; i++, dir = Path.GetDirectoryName(dir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*proj", Options))
                    if (IsProject(file) && string.Equals(IdOf(file), id, StringComparison.OrdinalIgnoreCase))
                        return new(file, IdOf(file)!);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // A folder that is gone or locked: the one above may still hold the project.
            }
        }
        return null;
    }

    /// <summary>The id a project file declares, or <c>null</c> when it declares none or can't be read.</summary>
    public static string? IdOf(string projectFile)
    {
        try
        {
            var info = new FileInfo(projectFile);
            return info.Exists && info.Length <= MaxProjectBytes ? IdIn(File.ReadAllText(projectFile)) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The <c>&lt;UserSecretsId&gt;</c> in a project file's text.</summary>
    public static string? IdIn(string projectXml) =>
        UserSecretsIdElement().Match(projectXml) is { Success: true } match ? match.Groups[1].Value : null;

    static bool IsProject(string file) => Extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(@"<UserSecretsId>\s*([^<\s]+)\s*</UserSecretsId>")]
    private static partial Regex UserSecretsIdElement();
}
