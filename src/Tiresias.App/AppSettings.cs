using System.Text.Json;
using Tiresias.Agent;
using Tiresias.Alerts;

namespace Tiresias.App;

/// <summary>The app's own preferences, <c>%LOCALAPPDATA%\Tiresias\app.json</c>. A missing or unreadable file means the defaults.</summary>
/// <param name="SetupSkipped">The user finished the first-run wizard without a broker.</param>
/// <param name="Alerts">Alert sinks narrowed without Windows Hello (muted, removed), by sink id; see <see cref="SinkNarrowing"/>.</param>
/// <param name="ReachScan">Whether the checks look inside the Docker engine: not yet, when asked, or daily.</param>
/// <param name="DeveloperTools">Whether developer tools show: when this PC looks like a developer's, always, or never (docs/developer-tools.md).</param>
/// <param name="DeveloperToolsNoted">The user closed Home's line saying why developer tools appeared.</param>
/// <param name="ApplyingUpdate">The version the app last quit to apply, until the next start checks it arrived.</param>
/// <param name="OnlineLookups">The user turned on the online trust lookups (docs/attack-surface.md#trust); off by default.</param>
/// <param name="AzSignOut">Whether the app signs the Azure CLI out: never, when Tiresias locks, or after the PC has been idle.</param>
/// <param name="AzSignOutIdleMinutes">The idle time for <see cref="Logic.AzSignOut.Idle"/>.</param>
public sealed record AppSettings(bool SetupSkipped = false, DateTimeOffset? LastUpdateCheck = null, IReadOnlyDictionary<string, SinkNarrowing>? Alerts = null, Logic.ReachScan ReachScan = Logic.ReachScan.Off,
    Logic.DeveloperToolsSetting DeveloperTools = Logic.DeveloperToolsSetting.Auto, bool DeveloperToolsNoted = false, string? ApplyingUpdate = null,
    bool OnlineLookups = false, Logic.AzSignOut AzSignOut = Logic.AzSignOut.Off, int AzSignOutIdleMinutes = Logic.AzSignOutPlan.DefaultIdleMinutes)
{
    static string Path => System.IO.Path.Combine(KeyringStore.Directory, "app.json");

    public static AppSettings Load()
    {
        try
        {
            return File.Exists(Path) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(Path), JsonSerializerOptions.Web) ?? new() : new();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            AppLog.Error(e, "app.json unreadable, using defaults");
            return new();
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(KeyringStore.Directory);
        File.WriteAllText(Path, JsonSerializer.Serialize(this, JsonSerializerOptions.Web));
    }
}
