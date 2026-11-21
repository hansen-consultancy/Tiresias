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

        var delivery = await StandaloneEnvironmentConsent.RequestAsync(["tool.exe", "two words", "one\nline"], terms,
            message =>
            {
                events.Add("prompt");
                Assert.That(message, Does.Contain("\"tool.exe\" \"two words\" \"one\\nline\""));
                Assert.That(message, Does.Contain("TOKEN (global, placeholder for feed, FEED_URL = http://127.0.0.1:1234/svc/feed)"));
                Assert.That(message, Does.Not.Contain("fixture-secret"));
                return allow;
            },
            () => snapshot.DeliverAsync(variables, Endpoint, (_, _) =>
            {
                events.Add("mint");
                return Task.FromResult(new MintedPlaceholder("fixture-placeholder"));
            }, _ => Task.CompletedTask, CancellationToken.None),
            approved => events.Add(approved ? "allow" : "deny"));

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
            _ => { current = false; return true; },
            () => snapshot.DeliverAsync(variables, Endpoint, (_, _) => throw new AssertionException("Unexpected mint."),
                _ => Task.CompletedTask, CancellationToken.None), decisions.Add));

        Assert.That(decisions, Is.Empty);
    }
}
