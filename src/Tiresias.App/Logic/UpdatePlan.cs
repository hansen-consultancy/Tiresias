namespace Tiresias.App.Logic;

/// <summary>
/// When the app looks for an update, and from where. It checks at start and then daily; a check
/// that failed (no network) isn't recorded, so it is retried at the next hourly tick instead of a
/// day later. Applying is always the user's click, never automatic, so an update can't cut a
/// consent dialog or an unsaved edit short.
/// </summary>
public static class UpdatePlan
{
    public static readonly TimeSpan Interval = TimeSpan.FromDays(1);

    /// <summary>How often the app asks itself whether a check is due.</summary>
    public static readonly TimeSpan Tick = TimeSpan.FromHours(1);

    public static bool IsDue(DateTimeOffset? lastCheck, DateTimeOffset now) => lastCheck is not { } last || now - last >= Interval || last > now;

    /// <summary>A preview build follows preview releases; a stable build only stable ones.</summary>
    public static bool FollowsPrereleases(string currentVersion) => currentVersion.Contains('-', StringComparison.Ordinal);

    /// <summary>
    /// The app quit to apply <paramref name="applying"/> and came back as another version: Velopack
    /// gave up (a folder it had to move was in use) and started the old one again without a word.
    /// </summary>
    public static bool ApplyFailed(string? applying, string currentVersion) =>
        applying is not null && !string.Equals(applying, currentVersion, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether <paramref name="path"/> is the install folder or inside it. A process whose program or
    /// working folder is there stops Velopack moving the folder, so the update can't be applied.
    /// </summary>
    public static bool InInstallFolder(string? path, string installRoot)
    {
        if (string.IsNullOrEmpty(path))
            return false;
        var root = Path.TrimEndingDirectorySeparator(installRoot);
        var full = Path.TrimEndingDirectorySeparator(path);
        return string.Equals(full, root, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
