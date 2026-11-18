namespace Tiresias.App.Logic;

/// <summary>
/// Which copy of the app this is. A copy the installer didn't put in place is a development build:
/// it says so wherever the version shows and its tray icon gets an orange corner, so a test never
/// runs against the installed copy by mistake.
/// </summary>
/// <param name="Commit">The short git commit the SDK appends to the informational version, if any.</param>
/// <param name="Folder">Where the running files are: two copies with the same folder are the same copy.</param>
public sealed record BuildInfo(string Version, string? Commit, bool Installed, string Folder)
{
    public bool Development => !Installed;

    /// <param name="informationalVersion">"0.1.0-preview.4" or "0.1.0-preview.4+5f91cdfe...".</param>
    public static BuildInfo From(string? informationalVersion, bool installed, string folder)
    {
        var parts = (informationalVersion ?? "0.0.0").Split('+', 2);
        var commit = parts.Length == 2 && parts[1].Length > 0 ? parts[1][..Math.Min(7, parts[1].Length)] : null;
        return new(parts[0], commit, installed, Trim(folder));
    }

    /// <summary>"0.1.0-preview.4", or "0.1.0-preview.2, development build 5f91cdf".</summary>
    public Phrase Label =>
        Installed ? new("Build_Installed", Version)
        : Commit is null ? new("Build_Development", Version)
        : new("Build_DevelopmentCommit", Version, Commit);

    /// <summary>The copy in <paramref name="folder"/> is this one, so a second start only brings it forward.</summary>
    public bool SameCopyAs(string? folder) => folder is not null && string.Equals(Folder, Trim(folder), StringComparison.OrdinalIgnoreCase);

    static string Trim(string folder) => folder.TrimEnd('\\', '/');
}
