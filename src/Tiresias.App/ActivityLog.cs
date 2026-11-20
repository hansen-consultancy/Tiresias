using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>The two local audit logs, read as activity entries: the agent's and the solo broker's.</summary>
static class ActivityLog
{
    /// <summary>Every record in both logs; slow on a long log, so read it off the UI thread.</summary>
    public static ActivityEntry[] ReadAll() =>
        [.. Read(AgentHost.ActivityPath, ActivitySource.UserSecrets).Concat(Read(SoloBroker.AuditPath, ActivitySource.Broker))];

    /// <summary>Reads one log, skipping what isn't a record; a missing or locked file reads as empty.</summary>
    static IEnumerable<ActivityEntry> Read(string path, ActivitySource source)
    {
        string[] lines;
        try
        {
            if (!File.Exists(path))
                return [];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, $"reading {path}");
            return [];
        }
        return lines.Select(l => ActivityQuery.Parse(l, source)).OfType<ActivityEntry>();
    }
}
