namespace Tiresias.App.Logic;

/// <summary>
/// Edits a <c>PATH</c> value (folders joined by <c>;</c>) so <c>tir</c> works in any new terminal.
/// Folders compare without case and without a trailing backslash; every other entry, and its
/// order and spelling, is kept as it was.
/// </summary>
public static class UserPath
{
    /// <returns>The value with <paramref name="folder"/> appended, or <c>null</c> when it is already there.</returns>
    public static string? With(string? path, string folder)
    {
        var entries = Split(path);
        if (entries.Any(e => Same(e, folder)))
            return null;
        return string.Join(';', [.. entries, folder]);
    }

    /// <returns>The value without <paramref name="folder"/>, or <c>null</c> when it wasn't there.</returns>
    public static string? Without(string? path, string folder)
    {
        var entries = Split(path);
        var kept = entries.Where(e => !Same(e, folder)).ToArray();
        return kept.Length == entries.Length ? null : string.Join(';', kept);
    }

    /// <summary>The folder holding <c>tir.exe</c>: beside the app when installed, <c>..\cli</c> when published from source.</summary>
    /// <returns><c>null</c> when neither has it (a plain <c>dotnet run</c>).</returns>
    public static string? TirFolder(string appFolder, Func<string, bool> fileExists)
    {
        var app = Trim(appFolder);
        if (fileExists(app + @"\tir.exe"))
            return app;
        var parent = app.LastIndexOf('\\') is var i and > 0 ? app[..i] : app;
        var cli = parent + @"\cli";
        return fileExists(cli + @"\tir.exe") ? cli : null;
    }

    static string[] Split(string? path) =>
        (path ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    static bool Same(string a, string b) => string.Equals(Trim(a), Trim(b), StringComparison.OrdinalIgnoreCase);

    // Windows paths spelled out rather than through Path, whose separators follow the OS the tests run on.
    static string Trim(string folder) => folder.TrimEnd('\\', '/');
}
