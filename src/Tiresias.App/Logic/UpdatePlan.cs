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
}
