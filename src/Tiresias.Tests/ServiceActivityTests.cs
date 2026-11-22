using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Audit;
using Tiresias.Client;

namespace Tiresias.Tests;

public class ServiceActivityTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    static string Record(string consumer) => JsonSerializer.Serialize(new { prevHash = AuditLog.Genesis, time = Now, kind = "Allow", consumer });

    [Test]
    public void Each_account_has_a_separate_journal_inside_the_service_only_folder()
    {
        const string owner = "S-1-5-21-1-2-3-1001";
        const string other = "S-1-5-21-1-2-3-1002";
        var config = new BrokerServiceConfig("vault.json", new string('a', 64), "UTC", owner);
        var journal = BrokerServiceLayout.BrokerSettings("state", config)["Broker:AuditPath"];

        Assert.That(journal, Is.EqualTo(BrokerServiceLayout.AuditPath("state", owner)));
        Assert.That(BrokerServiceLayout.BrokerSettings("state", config with { OwnerSid = other })["Broker:AuditPath"], Is.Not.EqualTo(journal));
        Assert.That(BrokerServiceLayout.StateFolderAcl("state"), Has.None.Contains(owner));
    }

    [Test, Platform("Win")]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void Only_the_local_enrolled_user_has_read_access_to_the_journal_pipe()
    {
        var owner = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var service = new SecurityIdentifier("S-1-5-80-1-2-3-4-5");
        var security = BrokerJournalAccess.For(owner, service);
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();
        var readers = rules.Where(r => r.AccessControlType == AccessControlType.Allow).ToList();

        Assert.That(readers.Select(r => r.IdentityReference), Is.EquivalentTo(new[] { owner, service }));
        Assert.That(readers.Single(r => r.IdentityReference == owner).PipeAccessRights, Is.EqualTo(PipeAccessRights.Read | PipeAccessRights.Synchronize));
        Assert.That(rules.Any(r => r.AccessControlType == AccessControlType.Deny && ((SecurityIdentifier)r.IdentityReference).IsWellKnown(WellKnownSidType.NetworkSid)), Is.True);
    }

    [Test, Platform("Win")]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task A_journal_connection_must_belong_to_the_expected_service_process()
    {
        var name = $"tiresias-test-{Guid.NewGuid():N}";
        using var server = new NamedPipeServerStream(name, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Task.WhenAll(server.WaitForConnectionAsync(timeout.Token), client.ConnectAsync(timeout.Token));

        Assert.That(ServicePipeIdentity.Matches(client, Environment.ProcessId), Is.True);
        Assert.That(ServicePipeIdentity.Matches(client, Environment.ProcessId + 1), Is.False);
        Assert.That(ServicePipeIdentity.Matches(client, 0), Is.False);
    }

    [Test]
    public void The_service_filter_and_current_totals_exclude_the_previous_app_broker()
    {
        var history = ActivityHistory.From([Record("app")], [Record("previous")], BrokerServiceState.Running, [Record("current")]);

        Assert.That(history.ServiceJournal, Is.EqualTo(ServiceJournalState.Available));
        Assert.That(history.Entries.Single(e => e.Source == ActivitySource.Broker).Consumer, Is.EqualTo("current"));
        Assert.That(history.Entries.Single(e => e.Source == ActivitySource.LegacyBroker).Consumer, Is.EqualTo("previous"));
        Assert.That(history.Today(Now), Is.EqualTo((2, 2)));
    }

    [Test]
    public void An_empty_service_journal_is_available_and_a_missing_journal_has_unknown_totals()
    {
        var empty = ActivityHistory.From([], [], BrokerServiceState.Running, []);
        var missing = ActivityHistory.From([], [Record("previous")], BrokerServiceState.Running, null);

        Assert.That(empty.ServiceJournal, Is.EqualTo(ServiceJournalState.Available));
        Assert.That(empty.Today(Now), Is.EqualTo((0, 0)));
        Assert.That(missing.ServiceJournal, Is.EqualTo(ServiceJournalState.Unavailable));
        Assert.That(missing.Entries.Single().Source, Is.EqualTo(ActivitySource.LegacyBroker));
        Assert.That(missing.Today(Now), Is.Null);
        var stopped = ActivityHistory.From([], [Record("previous")], BrokerServiceState.Stopped, null);
        Assert.That(stopped.ServiceJournal, Is.EqualTo(ServiceJournalState.Stopped));
        Assert.That(stopped.Today(Now), Is.Null);
    }

    [TestCase("[]")]
    [TestCase("{}")]
    public void An_unverifiable_journal_is_reported_as_unavailable_history(string line)
    {
        var history = ActivityHistory.From([], [], BrokerServiceState.Running, [Record("first"), line]);

        Assert.That(history.ServiceJournal, Is.EqualTo(ServiceJournalState.Invalid));
        Assert.That(history.Entries, Is.Empty);
        Assert.That(history.Today(Now), Is.Null);
    }

    [Test]
    public void The_in_app_broker_remains_the_current_source_without_a_service()
    {
        var history = ActivityHistory.From([], [Record("local")], BrokerServiceState.NotInstalled, null);

        Assert.That(history.ServiceJournal, Is.EqualTo(ServiceJournalState.InApp));
        Assert.That(history.Entries.Single().Source, Is.EqualTo(ActivitySource.Broker));
        Assert.That(history.Today(Now), Is.EqualTo((1, 1)));
    }
}
