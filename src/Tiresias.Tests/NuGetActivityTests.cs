using Tiresias.App.Logic;
using Tiresias.Audit;
using Tiresias.Client;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

/// <summary>What Activity shows for a NuGet credential request: every outcome, the program, feed and variable, never the token.</summary>
public class NuGetActivityTests
{
    const string Feed = "https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json";
    const string Program = @"C:\Program Files\Visual Studio\devenv.exe";

    [TestCase(NuGetOutcome.AllowedOnce, AuditKind.Allow, "allowed once")]
    [TestCase(NuGetOutcome.AllowedForSession, AuditKind.Allow, "allowed for this session")]
    [TestCase(NuGetOutcome.CoveredBySession, AuditKind.Allow, "allowed earlier for this session")]
    [TestCase(NuGetOutcome.Denied, AuditKind.Deny, "denied")]
    [TestCase(NuGetOutcome.RetryRefused, AuditKind.Deny, "retry after a refused token, not answered")]
    [TestCase(NuGetOutcome.NotSealed, AuditKind.Deny, "not sealed")]
    public void Each_outcome_names_the_program_the_feed_and_the_variable(NuGetOutcome outcome, AuditKind kind, string said)
    {
        var record = NuGetActivity.Record(outcome, Program, 4242, Feed, "AZDO_PAT");

        Assert.That(record, Is.EqualTo(new AuditRecord(kind, Consumer: "nuget", Service: Feed, Process: $"{Program} (pid 4242)", Reason: $"AZDO_PAT: {said}")));
    }

    [Test]
    public void Records_in_the_activity_log_are_found_by_the_source_outcome_and_text_filters()
    {
        var lines = Written(
            NuGetActivity.Record(NuGetOutcome.AllowedForSession, Program, 1, Feed, "AZDO_PAT"),
            NuGetActivity.Record(NuGetOutcome.RetryRefused, Program, 1, Feed, "AZDO_PAT"));
        var entries = lines.Select(l => ActivityQuery.Parse(l, ActivitySource.UserSecrets)).OfType<ActivityEntry>().ToArray();

        Assert.That(Reasons(entries, new(Outcome: ActivityOutcome.Allowed, Source: ActivitySource.UserSecrets)), Is.EqualTo(new[] { "AZDO_PAT: allowed for this session" }));
        Assert.That(Reasons(entries, new(Outcome: ActivityOutcome.Denied, Source: ActivitySource.UserSecrets)),
            Is.EqualTo(new[] { "AZDO_PAT: retry after a refused token, not answered" }));
        Assert.That(Reasons(entries, new(Source: ActivitySource.Broker)), Is.Empty);
        Assert.That(Reasons(entries, new(Text: "devenv")), Has.Length.EqualTo(2));
    }

    [Test]
    public void Only_an_allowed_hand_out_counts_as_the_program_using_the_feed()
    {
        var lines = Written(
            NuGetActivity.Record(NuGetOutcome.CoveredBySession, Program, 1, Feed, "AZDO_PAT"),
            NuGetActivity.Record(NuGetOutcome.Denied, Program, 1, Feed, "AZDO_PAT"));

        Assert.That(Doctor.CredentialUses(lines).Select(u => (u.Program, u.Service)), Is.EqualTo(new[] { (Program, Feed) }));
    }

    static string?[] Reasons(IEnumerable<ActivityEntry> entries, ActivityFilter filter) =>
        [.. ActivityQuery.Filter(entries, filter, DateTimeOffset.Now).Select(e => e.Reason)];

    /// <summary>The lines an <see cref="AuditLog"/> writes for <paramref name="records"/>, as the app's activity log holds them.</summary>
    static string[] Written(params AuditRecord[] records)
    {
        var dir = Directory.CreateTempSubdirectory("tiresias-nuget-activity");
        try
        {
            var path = Path.Combine(dir.FullName, "activity.jsonl");
            using (var log = new AuditLog(path, TimeProvider.System))
                foreach (var record in records)
                    log.Append(record);
            return File.ReadAllLines(path);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }
}
