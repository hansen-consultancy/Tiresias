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
        Read(ActivityLog.HasHistory, "activity log"),
        [.. fixes],
        [.. Opened]));

    /// <summary>
    /// The counts beside the places on the left and in the tray, each <c>null</c> when it couldn't be
    /// read. Reads files, the vault and the registry, so call it off the UI thread.
    /// </summary>
    public static NavCounts Counts()
    {
        var today = ActivityLog.ReadAll().Today(DateTimeOffset.Now);
        return new(
            Read(() => UserSecretsFiles.All().Count, "user secrets folders"),
            Read(() => VaultEditor.Load().Services.Count, "vault services"),
            Read(() => EnvironmentStore.UserVariables().Count, "user variables"),
            today?.Records,
            today?.Approvals);
    }

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

/// <summary>What each place on the left holds; <c>null</c> where it couldn't be read.</summary>
sealed record NavCounts(int? Secrets, int? Services, int? Variables, int? ActivityToday, int? ApprovalsToday);
