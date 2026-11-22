using Tiresias.Audit;
using Tiresias.Client;

namespace Tiresias.App.Logic;

public enum ServiceJournalState { InApp, Available, Stopped, Unavailable, Invalid }

public sealed record ActivityHistory(IReadOnlyList<ActivityEntry> Entries, ServiceJournalState ServiceJournal)
{
    /// <summary>While a service is installed only its verified journal represents current broker decisions.</summary>
    public static ActivityHistory From(IEnumerable<string> agent, IEnumerable<string> localBroker, BrokerServiceState? service,
        IReadOnlyList<string>? serviceJournal, IReadOnlyList<DateTimeOffset>? enrollmentApprovals = null)
    {
        var entries = Parse(agent, ActivitySource.UserSecrets).ToList();
        foreach (var time in enrollmentApprovals ?? [])
            entries.Add(new(time, ActivitySource.UserSecrets, AuditKind.Allow, null, "Recovery key enrollment", null,
                "The administrator approved recovery key enrollment.", null, null, null));
        entries.AddRange(Parse(localBroker, service == BrokerServiceState.NotInstalled ? ActivitySource.Broker : ActivitySource.LegacyBroker));
        if (service == BrokerServiceState.NotInstalled)
            return new(entries, ServiceJournalState.InApp);
        if (service == BrokerServiceState.Stopped)
            return new(entries, ServiceJournalState.Stopped);
        if (service is null || serviceJournal is null)
            return new(entries, ServiceJournalState.Unavailable);
        if (AuditLog.Verify(serviceJournal) is not null)
            return new(entries, ServiceJournalState.Invalid);
        var records = Parse(serviceJournal, ActivitySource.Broker).ToArray();
        if (records.Length != serviceJournal.Count)
            return new(entries, ServiceJournalState.Invalid);
        entries.AddRange(records);
        return new(entries, ServiceJournalState.Available);
    }

    public (int Records, int Approvals)? Today(DateTimeOffset now) =>
        ServiceJournal is ServiceJournalState.Unavailable or ServiceJournalState.Invalid or ServiceJournalState.Stopped
            ? null : ActivityQuery.Today(Entries.Where(e => e.Source != ActivitySource.LegacyBroker), now);

    static IEnumerable<ActivityEntry> Parse(IEnumerable<string> lines, ActivitySource source) =>
        lines.Select(l => ActivityQuery.Parse(l, source)).OfType<ActivityEntry>();
}
