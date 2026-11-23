using System.Text.RegularExpressions;
using System.Xml.Linq;
using Tiresias.App.Logic;
using Tiresias.Audit;

namespace Tiresias.Tests;

public class TrayStatusTests
{
    static readonly DateTimeOffset Until = new(2026, 11, 17, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public void Before_setup_only_finishing_setup_is_offered()
    {
        var view = TrayStatus.Describe(new(SetUp: false, Unlocked: false, Enrolled: false, Solo: false));

        Assert.That(view.Headline.Key, Is.EqualTo("Tray_NotSetUp"));
        Assert.That((view.OfferSetup, view.CanUnlock, view.CanLock), Is.EqualTo((true, false, false)));
    }

    [Test]
    public void Locked_offers_unlock_only()
    {
        var view = TrayStatus.Describe(new(SetUp: true, Unlocked: false, Enrolled: true, Solo: false));

        Assert.That(view.Headline.Key, Is.EqualTo("Tray_Locked"));
        Assert.That((view.CanUnlock, view.CanLock), Is.EqualTo((true, false)));
        Assert.That(view.Mode, Is.Null);
    }

    [Test]
    public void Unlocked_with_a_lease_shows_when_it_ends()
    {
        var view = TrayStatus.Describe(new(SetUp: true, Unlocked: true, Enrolled: true, Solo: true, LeaseUntil: Until));

        Assert.That(view.Headline.Key, Is.EqualTo("Tray_UnlockedUntil"));
        Assert.That(view.Headline.Args, Is.EqualTo(new object[] { Until.ToLocalTime() }));
        Assert.That(view.Mode?.Key, Is.EqualTo("Tray_ModeSolo"));
        Assert.That((view.CanUnlock, view.CanLock), Is.EqualTo((false, true)));
    }

    [Test]
    public void Unlocked_without_a_lease_offers_unlocking_again_to_retry_it()
    {
        var view = TrayStatus.Describe(new(SetUp: true, Unlocked: true, Enrolled: true, Solo: false));

        Assert.That(view.Headline.Key, Is.EqualTo("Tray_UnlockedNoLease"));
        Assert.That((view.CanUnlock, view.CanLock), Is.EqualTo((true, true)));
    }

    [Test]
    public void Without_a_broker_unlocked_means_user_secrets_only()
    {
        var view = TrayStatus.Describe(new(SetUp: true, Unlocked: true, Enrolled: false, Solo: false));

        Assert.That(view.Headline.Key, Is.EqualTo("Tray_UnlockedSecretsOnly"));
        Assert.That(view.CanUnlock, Is.False);
    }

    [Test]
    public void A_solo_broker_that_failed_to_start_says_so_and_offers_a_retry()
    {
        var view = TrayStatus.Describe(new(SetUp: true, Unlocked: true, Enrolled: true, Solo: true, BrokerProblem: "port 7780 in use"));

        Assert.That(view.Headline.Key, Is.EqualTo("Tray_BrokerDown"));
        Assert.That((view.CanUnlock, view.CanLock), Is.EqualTo((true, true)));
    }
}

public class FirstRunPlanTests
{
    static SetupFacts Facts(bool hello = false, bool recovery = false, bool enrolled = false, bool skipped = false) =>
        new(hello, recovery, enrolled, skipped);

    [Test]
    public void A_fresh_machine_starts_at_welcome_and_walks_every_step()
    {
        Assert.That(FirstRunPlan.Start(Facts()), Is.EqualTo(FirstRunStep.Welcome));
        Assert.That(FirstRunPlan.Next(FirstRunStep.Welcome, Facts()), Is.EqualTo(FirstRunStep.Hello));
        Assert.That(FirstRunPlan.Next(FirstRunStep.Hello, Facts(hello: true)), Is.EqualTo(FirstRunStep.RecoveryShow));
        Assert.That(FirstRunPlan.Next(FirstRunStep.RecoveryShow, Facts(hello: true)), Is.EqualTo(FirstRunStep.RecoveryConfirm));
        Assert.That(FirstRunPlan.Next(FirstRunStep.RecoveryConfirm, Facts(hello: true, recovery: true)), Is.EqualTo(FirstRunStep.Mode));
        Assert.That(FirstRunPlan.Next(FirstRunStep.Mode, Facts(hello: true, recovery: true), SetupMode.Solo, haveRecoveryKey: true),
            Is.EqualTo(FirstRunStep.Done));
    }

    [Test]
    public void Sealed_secrets_without_a_recovery_key_ask_for_theirs_before_making_a_new_one()
    {
        var copied = new SetupFacts(HelloReady: true, RecoverySet: false, Enrolled: false, Skipped: false, SealedWithoutKey: true);
        Assert.That(FirstRunPlan.Next(FirstRunStep.Hello, copied), Is.EqualTo(FirstRunStep.RecoveryRestore));
        Assert.That(FirstRunPlan.Start(copied), Is.EqualTo(FirstRunStep.RecoveryRestore));
        Assert.That(FirstRunPlan.Next(FirstRunStep.RecoveryRestore, copied with { RecoverySet = true }), Is.EqualTo(FirstRunStep.Mode));
        Assert.That(FirstRunPlan.Next(FirstRunStep.RecoveryRestore, copied with { RecoverySet = true, Enrolled = true }), Is.EqualTo(FirstRunStep.Done));
    }

    [TestCase(true, false, false, false, FirstRunStep.RecoveryShow)]
    [TestCase(false, true, false, false, FirstRunStep.Hello)]
    [TestCase(true, true, false, false, FirstRunStep.Mode)]
    [TestCase(true, true, true, false, FirstRunStep.Done)]
    [TestCase(true, true, false, true, FirstRunStep.Done)]
    public void An_interrupted_setup_resumes_at_the_first_thing_missing(bool hello, bool recovery, bool enrolled, bool skipped, FirstRunStep expected) =>
        Assert.That(FirstRunPlan.Start(Facts(hello, recovery, enrolled, skipped)), Is.EqualTo(expected));

    [Test]
    public void Welcome_skips_hello_when_the_credential_already_exists() =>
        Assert.That(FirstRunPlan.Next(FirstRunStep.Welcome, Facts(hello: true)), Is.EqualTo(FirstRunStep.RecoveryShow));

    [Test]
    public void Resumed_solo_setup_asks_for_the_recovery_key_back_since_it_is_never_shown_twice() =>
        Assert.That(FirstRunPlan.Next(FirstRunStep.Mode, Facts(hello: true, recovery: true), SetupMode.Solo, haveRecoveryKey: false),
            Is.EqualTo(FirstRunStep.RecoveryType));

    [TestCase(SetupMode.Broker)]
    [TestCase(SetupMode.SecretsOnly)]
    public void Choosing_another_mode_finishes_without_the_key(SetupMode mode) =>
        Assert.That(FirstRunPlan.Next(FirstRunStep.Mode, Facts(hello: true, recovery: true), mode), Is.EqualTo(FirstRunStep.Done));

    [Test]
    public void Skipping_the_broker_counts_as_set_up()
    {
        Assert.That(FirstRunPlan.Needed(Facts(hello: true, recovery: true)), Is.True);
        Assert.That(FirstRunPlan.Needed(Facts(hello: true, recovery: true, skipped: true)), Is.False);
    }

    [TestCase(0, 0, true)]
    [TestCase(1, 0, false)]
    [TestCase(0, 1, false)]
    public void A_lost_recovery_key_is_replaceable_only_while_nothing_is_sealed_to_it(int vault, int sealedFiles, bool expected) =>
        Assert.That(FirstRunPlan.CanReplaceRecoveryKey(vault, sealedFiles), Is.EqualTo(expected));
}

public class ActivityQueryTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);

    static ActivityEntry Entry(AuditKind kind, int daysAgo = 0, ActivitySource source = ActivitySource.Broker, string? service = "github") =>
        new(Now.AddDays(-daysAgo).AddMinutes(-1), source, kind, "alice", service, @"C:\tools\gh.exe", null, "GET", "/user", 200);

    [Test]
    public void Reads_the_lines_the_audit_log_writes()
    {
        var dir = Directory.CreateTempSubdirectory("tiresias-activity");
        try
        {
            var path = Path.Combine(dir.FullName, "audit.jsonl");
            using (var log = new AuditLog(path, TimeProvider.System))
                log.Append(new AuditRecord(AuditKind.Deny, Consumer: "alice", Service: "github", Reason: "outside the grant"));

            var entry = ActivityQuery.Parse(File.ReadAllLines(path)[0], ActivitySource.Broker);

            Assert.That(entry, Is.Not.Null);
            Assert.That((entry!.Kind, entry.Consumer, entry.Service, entry.Reason), Is.EqualTo((AuditKind.Deny, "alice", "github", "outside the grant")));
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    [TestCase("")]
    [TestCase("{\"time\":")]
    [TestCase("not json")]
    public void A_torn_or_foreign_line_is_skipped(string line) =>
        Assert.That(ActivityQuery.Parse(line, ActivitySource.UserSecrets), Is.Null);

    [Test]
    public void Filters_by_outcome_source_period_and_text_newest_first()
    {
        ActivityEntry[] all =
        [
            Entry(AuditKind.Allow, daysAgo: 0),
            Entry(AuditKind.Deny, daysAgo: 1),
            Entry(AuditKind.Allow, daysAgo: 10),
            Entry(AuditKind.Allow, daysAgo: 2, source: ActivitySource.UserSecrets, service: "my-app"),
        ];

        Assert.That(ActivityQuery.Filter(all, new(), Now), Has.Count.EqualTo(3));
        Assert.That(ActivityQuery.Filter(all, new(Period: ActivityPeriod.All), Now), Has.Count.EqualTo(4));
        Assert.That(ActivityQuery.Filter(all, new(Outcome: ActivityOutcome.Denied), Now).Single().Kind, Is.EqualTo(AuditKind.Deny));
        Assert.That(ActivityQuery.Filter(all, new(Source: ActivitySource.UserSecrets), Now).Single().Service, Is.EqualTo("my-app"));
        Assert.That(ActivityQuery.Filter(all, new(Text: "MY-APP"), Now), Has.Count.EqualTo(1));
        Assert.That(ActivityQuery.Filter(all, new(Period: ActivityPeriod.All), Now).Select(e => e.Time), Is.Ordered.Descending);
    }

    [Test]
    public void Today_counts_records_since_local_midnight_and_the_approvals_among_them()
    {
        var midnight = new DateTimeOffset(Now.ToLocalTime().Date, Now.ToLocalTime().Offset);
        ActivityEntry At(AuditKind kind, DateTimeOffset time) => Entry(kind) with { Time = time };
        ActivityEntry[] all =
        [
            At(AuditKind.Allow, midnight.AddMinutes(1)),
            At(AuditKind.Allow, midnight.AddMinutes(2)),
            At(AuditKind.Deny, midnight.AddMinutes(3)),
            At(AuditKind.Allow, midnight.AddMinutes(-1)),
        ];

        Assert.That(ActivityQuery.Today(all, Now), Is.EqualTo((3, 2)));
    }

    [Test]
    public void Lists_at_most_the_limit()
    {
        var many = Enumerable.Range(0, ActivityQuery.Limit + 5).Select(_ => Entry(AuditKind.Allow));

        Assert.That(ActivityQuery.Filter(many, new(), Now), Has.Count.EqualTo(ActivityQuery.Limit));
    }

    [Test]
    public void Every_kind_has_words_of_its_own()
    {
        foreach (var kind in Enum.GetValues<AuditKind>())
            Assert.That(ActivityQuery.Describe(kind).Key, Is.EqualTo($"Kind_{kind}"));
    }
}

public class ProblemsTests
{
    [Test]
    public void Every_problem_says_what_happened_why_it_matters_and_what_to_do()
    {
        foreach (var kind in Enum.GetValues<ProblemKind>())
        {
            var p = Problems.Explain(kind);
            Assert.That(p.Kind, Is.EqualTo(kind));
            Assert.That(new[] { p.Title.Key, p.What.Key, p.Why.Key, p.Next.Key },
                Is.EqualTo(new[] { $"Problem_{kind}_Title", $"Problem_{kind}_What", $"Problem_{kind}_Why", $"Problem_{kind}_Next" }));
        }
    }

    [Test]
    public void Details_carry_the_message_and_the_log_but_no_stack_trace()
    {
        Exception e;
        try
        {
            throw new InvalidOperationException("The broker refused the lease.");
        }
        catch (InvalidOperationException caught)
        {
            e = caught;
        }

        var text = Problems.Details(Problems.Explain(ProblemKind.BrokerRefused), e.Message, "0.1.0", @"C:\Users\alice\app.log",
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero));

        Assert.That(text, Does.Contain("BrokerRefused").And.Contain("The broker refused the lease.").And.Contain("app.log"));
        Assert.That(text, Does.Not.Contain(" at ").And.Not.Contain(nameof(Details_carry_the_message_and_the_log_but_no_stack_trace)));
    }
}

/// <summary>All the app's words are in Strings.resx: each key the app uses exists there, and each key there is used.</summary>
public class AppStringsTests
{
    static readonly string App = Path.Combine(RepoRoot(), "src", "Tiresias.App");

    static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Tiresias.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Tiresias.slnx not found above the test directory.");
    }

    static HashSet<string> Defined() =>
        XDocument.Load(Path.Combine(App, "Strings.resx")).Root!.Elements("data").Select(d => (string)d.Attribute("name")!).ToHashSet();

    /// <summary>Keys are <c>Area_Name</c> string literals in code and <c>{l:S Key}</c> in XAML; problem keys are built from the enum.</summary>
    static HashSet<string> Used()
    {
        var used = new HashSet<string>();
        foreach (var file in Directory.EnumerateFiles(App, "*.cs", SearchOption.AllDirectories))
            foreach (Match m in Regex.Matches(File.ReadAllText(file), "\"([A-Z][A-Za-z0-9]*_[A-Za-z0-9_]+)\""))
                used.Add(m.Groups[1].Value);
        foreach (var file in Directory.EnumerateFiles(App, "*.xaml", SearchOption.AllDirectories))
            foreach (Match m in Regex.Matches(File.ReadAllText(file), @"\{l:S ([A-Za-z0-9_]+)\}"))
                used.Add(m.Groups[1].Value);
        return used;
    }

    [Test]
    public void Every_key_the_app_uses_is_defined() =>
        Assert.That(Used().Except(Defined()), Is.Empty);

    [Test]
    public void Every_defined_key_is_used() =>
        Assert.That(Defined().Except(Used()), Is.Empty);

    [Test]
    public void No_value_is_empty() =>
        Assert.That(XDocument.Load(Path.Combine(App, "Strings.resx")).Root!.Elements("data")
            .Where(d => string.IsNullOrWhiteSpace((string?)d.Element("value"))).Select(d => (string)d.Attribute("name")!), Is.Empty);
}

public class UpdatePlanTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void Checks_at_first_start_then_daily()
    {
        Assert.That(UpdatePlan.IsDue(null, Now), Is.True);
        Assert.That(UpdatePlan.IsDue(Now.AddHours(-23), Now), Is.False);
        Assert.That(UpdatePlan.IsDue(Now.AddHours(-24), Now), Is.True);
    }

    [Test]
    public void A_last_check_in_the_future_after_a_clock_change_does_not_stop_checks() =>
        Assert.That(UpdatePlan.IsDue(Now.AddDays(3), Now), Is.True);

    [TestCase("0.1.0-preview.3", true)]
    [TestCase("0.1.0", false)]
    [TestCase("1.2.0", false)]
    public void A_preview_build_follows_preview_releases(string version, bool expected) =>
        Assert.That(UpdatePlan.FollowsPrereleases(version), Is.EqualTo(expected));

    [TestCase(null, "0.3.0", false)]
    [TestCase("0.3.0", "0.3.0", false)]
    [TestCase("0.3.0", "0.2.1", true)]
    public void An_apply_failed_when_the_app_came_back_as_another_version(string? applying, string current, bool expected) =>
        Assert.That(UpdatePlan.ApplyFailed(applying, current), Is.EqualTo(expected));

    [TestCase("TiresiasApp/current/", true)]
    [TestCase("TiresiasApp", true)]
    [TestCase("tiresiasapp/current/Tiresias.exe", true)]
    [TestCase("TiresiasAppOld/current", false)]
    [TestCase("", false)]
    [TestCase(null, false)]
    public void A_program_or_working_folder_in_the_install_folder_blocks_an_update(string? relative, bool expected)
    {
        // Built with the platform's separator: CI also runs on Linux.
        static string Under(string relative) =>
            Path.Join(Path.GetTempPath(), "u", relative.Replace('/', Path.DirectorySeparatorChar));
        var path = relative is null ? null : Under(relative);
        Assert.That(UpdatePlan.InInstallFolder(path, Under("TiresiasApp/")), Is.EqualTo(expected));
    }
}

public class DetailTextTests
{
    [Test]
    public void Empty_values_are_left_out() =>
        Assert.That(DetailText.Shown([new("Name", "alice"), new("Version", ""), new("Folder", "  ")]).Select(f => f.Label),
            Is.EqualTo(new[] { "Name" }));

    [Test]
    public void Copy_puts_one_label_and_value_per_line() =>
        Assert.That(DetailText.Format([new("Name", "alice"), new("Version", ""), new("Upstream", "https://example.com/api")]),
            Is.EqualTo($"Name: alice{Environment.NewLine}Upstream: https://example.com/api"));

    [Test]
    public void A_value_of_several_lines_stays_under_its_label() =>
        Assert.That(DetailText.Format([new("Grants", "read\r\nwrite")]),
            Is.EqualTo($"Grants: read{Environment.NewLine}  write"));
}
