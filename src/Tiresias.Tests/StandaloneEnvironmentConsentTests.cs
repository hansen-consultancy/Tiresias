using Tiresias.EnvironmentVariables;
using Tiresias.Keyring;

namespace Tiresias.Tests;

public class StandaloneEnvironmentConsentTests
{
    static readonly Uri Endpoint = new("http://127.0.0.1:1234");

    [TestCase(false)]
    [TestCase(true)]
    public async Task The_user_sees_the_command_and_delivery_terms_before_any_release(bool allow)
    {
        var environment = SealedEnvironment.Empty.WithGlobal([new("TOKEN", "fixture-secret")])
            .WithPlaceholder(new("TOKEN", "feed", "FEED_URL"));
        var snapshot = new EnvironmentSnapshot(environment, () => { });
        var (variables, _, terms) = snapshot.SelectForCommand(null, null, Endpoint);
        var events = new List<string>();

        var answer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = StandaloneEnvironmentConsent.RequestAsync(["tool.exe", "two words", "one\nline"], terms,
            (arguments, shownTerms) =>
            {
                events.Add("prompt");
                Assert.That(arguments, Is.EqualTo(new[] { "tool.exe", "two words", "one\nline" }));
                Assert.That(shownTerms, Is.EqualTo(new[] { "TOKEN (global, placeholder for feed, FEED_URL = http://127.0.0.1:1234/svc/feed)" }));
                return answer.Task;
            },
            () => snapshot.DeliverAsync(variables, Endpoint, (_, _) =>
            {
                events.Add("mint");
                return Task.FromResult(new MintedPlaceholder("fixture-placeholder"));
            }, _ => Task.CompletedTask, CancellationToken.None),
            approved => events.Add(approved ? "allow" : "deny"));

        Assert.That(events, Is.EqualTo(new[] { "prompt" }));
        Assert.That(request.IsCompleted, Is.False);
        answer.SetResult(allow);
        var delivery = await request;
        Assert.That(events, Is.EqualTo(allow ? new[] { "prompt", "mint", "allow" } : ["prompt", "deny"]));
        if (allow)
            Assert.That(delivery!.Variables["TOKEN"], Is.EqualTo("fixture-placeholder"));
        else
            Assert.That(delivery, Is.Null);
    }

    [Test]
    public void A_policy_change_while_the_dialog_is_open_cannot_be_recorded_as_an_approval()
    {
        var current = true;
        var snapshot = new EnvironmentSnapshot(SealedEnvironment.Empty.WithGlobal([new("TOKEN", "fixture-secret")]), () =>
        {
            if (!current)
                throw EnvironmentIntegrityException.Changed();
        });
        var (variables, _, terms) = snapshot.SelectForCommand(null, null, Endpoint);
        var decisions = new List<bool>();

        Assert.ThrowsAsync<EnvironmentIntegrityException>(() => StandaloneEnvironmentConsent.RequestAsync(["tool.exe"], terms,
            (_, _) => { current = false; return Task.FromResult(true); },
            () => snapshot.DeliverAsync(variables, Endpoint, (_, _) => throw new AssertionException("Unexpected mint."),
                _ => Task.CompletedTask, CancellationToken.None), decisions.Add));

        Assert.That(decisions, Is.Empty);
    }

    [TestCase(false)]
    [TestCase(true)]
    public void An_unavailable_dialog_records_a_denial_before_any_release(bool asynchronousFailure)
    {
        var decisions = new List<bool>();
        var failure = new FileNotFoundException("Private fixture detail.");
        var error = Assert.ThrowsAsync<InvalidOperationException>(() => StandaloneEnvironmentConsent.RequestAsync(["tool.exe"], ["TOKEN (global, raw value)"],
            (_, _) => asynchronousFailure ? Task.FromException<bool>(failure) : throw failure,
            () => throw new AssertionException("Unexpected delivery."), decisions.Add));

        Assert.That(error!.Message, Is.EqualTo("The Tiresias consent dialog was unavailable. The command was stopped."));
        Assert.That(decisions, Is.EqualTo(new[] { false }));
    }

    [Test]
    public async Task A_command_with_no_sealed_variables_needs_no_consent()
    {
        var snapshot = new EnvironmentSnapshot(SealedEnvironment.Empty, () => { });
        var (variables, _, terms) = snapshot.SelectForCommand(null, null, Endpoint);
        var decisions = new List<bool>();

        var delivery = await StandaloneEnvironmentConsent.RequestAsync(["tool.exe"], terms,
            (_, _) => throw new AssertionException("Unexpected prompt."),
            () => snapshot.DeliverAsync(variables, Endpoint, (_, _) => throw new AssertionException("Unexpected mint."),
                _ => Task.CompletedTask, CancellationToken.None), decisions.Add);

        Assert.That(delivery!.Variables, Is.Empty);
        Assert.That(decisions, Is.EqualTo(new[] { true }));
    }
}
