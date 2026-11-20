using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Protocol;

namespace Tiresias.App;

/// <summary>
/// Reads the facts <see cref="HomeAreas"/> decides from: names, counts and file sizes, all readable
/// while locked. Home and the tray menu both ask here, so they agree. UI thread only.
/// </summary>
static class Home
{
    static readonly HashSet<HomeArea> Opened = [];

    /// <summary>How many findings Home showed the last time it checked; <c>null</c> until it has, this session.</summary>
    public static int? LastFindings { get; set; }

    /// <summary>An area opened from <i>What do you need?</i> stays on Home for the rest of the session.</summary>
    public static void Open(HomeArea area) => Opened.Add(area);

    public static IReadOnlySet<HomeArea> Areas(IEnumerable<DoctorFix> fixes) => HomeAreas.Plan(new(
        Read(() => VaultEditor.Load().Services.Count, "vault services"),
        Read(() => UserSecretsFiles.All().Any(f => f.Kind == SecretsFileKind.Sealed), "sealed user secrets"),
        Read(() => ProjectIndexStore.Load().Folders.Count > 0, "project folders"),
        Read(() => EnvironmentStore.IsSealed, "sealed variables"),
        Read(() => HasRecord(AgentHost.ActivityPath) || HasRecord(SoloBroker.AuditPath), "activity log"),
        [.. fixes],
        [.. Opened]));

    static bool HasRecord(string path) => new FileInfo(path) is { Exists: true, Length: > 0 };

    static T? Read<T>(Func<T> read, string what) where T : struct
    {
        try
        {
            return read();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
        {
            AppLog.Error(e, $"home: reading {what}");
            return null;
        }
    }
}
