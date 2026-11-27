using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace Tiresias.App.Logic;

/// <summary>
/// About's <i>Sign the Azure CLI out</i>: the Azure CLI keeps its Entra session until told otherwise
/// and has no timeout of its own, so the app can end it (docs/desktop-app.md).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<AzSignOut>))]
public enum AzSignOut
{
    /// <summary>Leave it signed in.</summary>
    Off,
    /// <summary>Whenever Tiresias locks, whatever locked it.</summary>
    OnLock,
    /// <summary>Once the PC has had no keyboard or mouse input for the chosen time.</summary>
    Idle,
}

public static class AzSignOutPlan
{
    /// <summary>The idle times About offers, in minutes.</summary>
    public static readonly ImmutableArray<int> IdleChoices = [5, 15, 30, 60, 120];

    public const int DefaultIdleMinutes = 30;

    /// <summary>The saved idle time, or the default when <c>app.json</c> holds one About doesn't offer.</summary>
    public static int IdleMinutes(int saved) => IdleChoices.Contains(saved) ? saved : DefaultIdleMinutes;

    /// <summary>Whether a lock of Tiresias signs the Azure CLI out.</summary>
    public static bool OnLock(AzSignOut setting) => setting == AzSignOut.OnLock;

    /// <summary>
    /// One look at how long the PC has been idle. Signs out once per idle stretch: <paramref name="done"/>
    /// is what the last look returned, and input (idle below the time again) clears it, so a sign-out
    /// that failed isn't tried every minute and a sign-in while away isn't undone twice.
    /// </summary>
    public static (bool SignOut, bool Done) OnIdle(AzSignOut setting, int minutes, TimeSpan idle, bool done) =>
        setting != AzSignOut.Idle || idle < TimeSpan.FromMinutes(IdleMinutes(minutes)) ? (false, false) : (!done, true);

    static readonly string[] Names = ["az.cmd", "az.bat", "az.exe"];

    /// <summary>
    /// The Azure CLI as <c>PATH</c> finds it: the first folder holding it. It is a batch file run
    /// through <c>cmd</c>, so only a full path is taken (never one relative to wherever the app runs),
    /// and never one <c>cmd</c> would rewrite (<c>%</c>, <c>"</c>).
    /// </summary>
    public static string? Find(string? path, Func<string, bool> exists)
    {
        foreach (var entry in (path ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var folder = entry.Trim('"');
            if (folder.Length == 0 || folder.AsSpan().ContainsAny('%', '"') || !Path.IsPathFullyQualified(folder))
                continue;
            foreach (var name in Names)
                if (Path.Combine(folder, name) is var file && exists(file))
                    return file;
        }
        return null;
    }
}
