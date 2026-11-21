using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Audit;
using Tiresias.Client;

namespace Tiresias.Tests;

public class UnlockActivityTests
{
    string path = null!;

    [SetUp]
    public void SetUp() => path = Path.GetTempFileName();

    [TearDown]
    public void TearDown() => File.Delete(path);

    [TestCase(HelloProblem.Cancelled, "Windows Hello prompt was cancelled.")]
    [TestCase(HelloProblem.Expired, "Windows Hello prompt expired.")]
    public void Failed_prompts_appear_once_under_denied_app_activity(HelloProblem problem, string reason)
    {
        using var activity = new AuditLog(path, TimeProvider.System);
        var failure = new HelloException(problem, "private diagnostic detail");

        var thrown = Assert.Throws<HelloException>(() => UnlockActivity.Run(() => throw failure, activity));

        Assert.That(thrown, Is.SameAs(failure));
        var lines = File.ReadAllLines(path);
        Assert.That(lines, Has.Length.EqualTo(1));
        Assert.That(lines[0], Does.Not.Contain(failure.Message));
        var history = ActivityHistory.From(lines, [], BrokerServiceState.Running, []);
        var filter = new ActivityFilter(Outcome: ActivityOutcome.Denied, Source: ActivitySource.UserSecrets, Period: ActivityPeriod.All);
        var entry = ActivityQuery.Filter(history.Entries, filter, DateTimeOffset.UtcNow).Single();
        Assert.That(entry.Kind, Is.EqualTo(AuditKind.Deny));
        Assert.That(entry.Service, Is.EqualTo("Windows Hello unlock"));
        Assert.That(entry.Reason, Is.EqualTo(reason));
        Assert.That(entry.Process, Is.Null);
    }

    [Test]
    public void Successful_unlock_does_not_add_a_denial()
    {
        using var activity = new AuditLog(path, TimeProvider.System);
        var attempts = 0;

        UnlockActivity.Run(() => attempts++, activity);

        Assert.That(attempts, Is.EqualTo(1));
        Assert.That(File.ReadAllLines(path), Is.Empty);
    }

    [Test]
    public void Unavailable_hello_keeps_its_original_error_without_recording_a_user_decision()
    {
        using var activity = new AuditLog(path, TimeProvider.System);
        var failure = new HelloException(HelloProblem.Unavailable, "Windows Hello is unavailable.");

        var thrown = Assert.Throws<HelloException>(() => UnlockActivity.Run(() => throw failure, activity));

        Assert.That(thrown, Is.SameAs(failure));
        Assert.That(File.ReadAllLines(path), Is.Empty);
    }
}
