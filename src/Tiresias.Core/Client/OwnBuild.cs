namespace Tiresias.Client;

/// <summary>What the disk says around a program file, for <see cref="OwnBuild.Looks"/>: read without starting anything or admin rights.</summary>
public interface IBuildDisk
{
    /// <summary>Folders any download or program can drop a file into (Temp, Downloads, AppData and the browser caches in it).</summary>
    IReadOnlyCollection<string> DropFolders { get; }

    /// <summary>Whether a file or folder exists.</summary>
    bool Exists(string path);

    /// <summary>The names of the files directly in a folder; none when it can't be read.</summary>
    IEnumerable<string> FileNames(string folder);

    /// <summary>Whether the current user owns the file.</summary>
    bool OwnedByYou(string file);
}

/// <summary>
/// Whether an unsigned program looks like the user's own build (docs/attack-surface.md, <b>Built by
/// you</b>): it sits in a git work tree that also holds the project that produced it (<c>obj</c>
/// beside its <c>bin</c>, or a project or solution file in a folder above it), and the user owns it.
/// Only a program with no signature at all qualifies: a signature that doesn't verify is a reason to
/// doubt, not a build. Nothing in a folder any download can write to (<see cref="IBuildDisk.DropFolders"/>)
/// qualifies either. It says what the disk looks like, not who wrote the code.
/// </summary>
public static class OwnBuild
{
    static readonly string[] ProjectExtensions = [".csproj", ".fsproj", ".vbproj", ".vcxproj", ".sln", ".slnx"];

    /// <param name="program">The program file's full Windows path.</param>
    /// <param name="valid">Its signature's verdict; <c>null</c> when it couldn't be checked.</param>
    /// <param name="signer">The name in its signature, present or not valid; <c>null</c> when it carries none.</param>
    public static bool Looks(string program, bool? valid, string? signer, IBuildDisk disk)
    {
        if (valid != false || signer is not null || !FullPath(program) || disk.DropFolders.Any(f => IsUnder(program, f)))
            return false;
        var project = false;
        string? from = null;
        foreach (var folder in Parents(program))
        {
            project = project
                || from is not null && Name(from).Equals("bin", StringComparison.OrdinalIgnoreCase) && disk.Exists(folder + @"\obj")
                || disk.FileNames(folder).Any(f => ProjectExtensions.Any(e => f.EndsWith(e, StringComparison.OrdinalIgnoreCase)));
            if (disk.Exists(folder + @"\.git"))
                return project && disk.OwnedByYou(program);
            from = folder;
        }
        return false;
    }

    /// <summary>The folders holding <paramref name="path"/>, nearest first, down to the drive's root (<c>C:</c>).</summary>
    static IEnumerable<string> Parents(string path)
    {
        for (var end = path.TrimEnd('\\', '/').LastIndexOfAny(['\\', '/']); end >= 2; end = path.LastIndexOfAny(['\\', '/'], end - 1))
            yield return path[..end];
    }

    static string Name(string folder) => folder[(folder.LastIndexOfAny(['\\', '/']) + 1)..];

    static bool FullPath(string path) => path.Length > 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] is '\\' or '/' && !path.Contains("..", StringComparison.Ordinal);

    static bool IsUnder(string path, string folder)
    {
        var root = folder.TrimEnd('\\', '/');
        return root.Length > 0 && path.Length > root.Length && path.StartsWith(root, StringComparison.OrdinalIgnoreCase) && path[root.Length] is '\\' or '/';
    }
}
