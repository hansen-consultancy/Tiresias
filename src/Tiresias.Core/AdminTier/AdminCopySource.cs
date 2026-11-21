namespace Tiresias.AdminTier;

/// <summary>
/// Whether the elevated install step may copy a file from the app's <c>admin\</c> folder, which the
/// user can write to. A link there could point at a file only administrators can read; copied
/// elevated into <c>%ProgramFiles%</c>, its contents would become readable by every user. So a file
/// is copied only when it is itself what its path names: no reparse point, one hard link, and its
/// final path, read from the open handle, inside the source folder.
/// </summary>
public static class AdminCopySource
{
    /// <param name="sourceRoot">The source folder's own final path, read from its handle.</param>
    /// <param name="finalPath">The final path of the open file (<c>GetFinalPathNameByHandle</c>), with or without <c>\\?\</c>.</param>
    /// <returns>Why the file is refused, or <c>null</c> to copy it.</returns>
    public static string? Refusal(string sourceRoot, FileAttributes attributes, uint links, string finalPath)
    {
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
            return "is a link";
        if (attributes.HasFlag(FileAttributes.Directory))
            return "is a folder where a file was expected";
        if (links != 1)
            return $"has {links} hard links";
        var root = Normal(sourceRoot).TrimEnd('\\') + '\\';
        return Normal(finalPath).StartsWith(root, StringComparison.OrdinalIgnoreCase) ? null : "resolves outside the source folder";
    }

    /// <summary>A folder in the source tree: walked only when it is no link.</summary>
    public static string? FolderRefusal(FileAttributes attributes) =>
        attributes.HasFlag(FileAttributes.ReparsePoint) ? "is a link" : null;

    /// <summary><c>\\?\C:\x</c> and <c>C:\x</c> are one path; <c>\\?\UNC\host\share</c> is <c>\\host\share</c>.</summary>
    static string Normal(string path) =>
        path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? @"\\" + path[8..]
        : path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..]
        : path;
}
