using System.ComponentModel;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App;

/// <summary>Reads local activity and the enrolled account's broker journal, including while locked.</summary>
static class ActivityLog
{
    public static bool HasHistory() => new FileInfo(AgentHost.ActivityPath) is { Exists: true, Length: > 0 }
        || new FileInfo(AgentHost.RecoveryActivityPath) is { Exists: true, Length: > 0 }
        || new FileInfo(SoloBroker.AuditPath) is { Exists: true, Length: > 0 } || ServiceState() != BrokerServiceState.NotInstalled
        || ReadEnrollmentApprovals().Count > 0;

    public static ActivityHistory ReadAll()
    {
        var state = ServiceState();
        IReadOnlyList<string>? serviceJournal = null;
        try
        {
            if (state == BrokerServiceState.Running)
                serviceJournal = BrokerService.ReadJournalAsync().GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception
            or System.Security.SecurityException or TimeoutException or OperationCanceledException or System.Text.Json.JsonException)
        {
            AppLog.Error(e, "reading the broker service journal");
        }
        return ActivityHistory.From((Read(AgentHost.ActivityPath) ?? []).Concat(Read(AgentHost.RecoveryActivityPath) ?? []), Read(SoloBroker.AuditPath) ?? [], state, serviceJournal, ReadEnrollmentApprovals());
    }

    static IReadOnlyList<DateTimeOffset> ReadEnrollmentApprovals()
    {
        try { return RecoveryKey.EnrollmentApprovalTimes(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            AppLog.Error(e, "reading recovery enrollment approvals");
            return [];
        }
    }

    static BrokerServiceState? ServiceState()
    {
        try
        {
            return DemoMode.On ? BrokerServiceState.NotInstalled : BrokerService.State();
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            AppLog.Error(e, "checking the broker service");
            return null;
        }
    }

    static List<string>? Read(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var lines = new List<string>();
            while (reader.ReadLine() is { } line)
                lines.Add(line);
            return lines;
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, $"reading {path}");
            return null;
        }
    }
}
