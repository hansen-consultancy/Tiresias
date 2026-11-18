using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

/// <summary>Variables handed out as a broker placeholder instead of their value.</summary>
public class EnvironmentPlaceholderTests
{
    static readonly Uri Forwarder = new("http://127.0.0.1:7781");

    static readonly SealedEnvironment Sealed = SealedEnvironment.Empty
        .WithGlobal([new("OPENAI_API_KEY", "sk-real"), new("DB_PASSWORD", "hunter2")])
        .WithPlaceholder(new("OPENAI_API_KEY", "openai", "OPENAI_BASE_URL"));

    [TestCase("OPENAI_API_KEY", "OPENAI_BASE_URL")]
    [TestCase("anthropic_key", "ANTHROPIC_BASE_URL")]
    [TestCase("HF_TOKEN", "HF_BASE_URL")]
    [TestCase("_KEY", null)]
    [TestCase("PASSWORD", null)]
    public void The_base_url_variable_follows_the_key_s_name(string variable, string? expected) =>
        Assert.That(SealedEnvironment.BaseUrlVariableFor(variable), Is.EqualTo(expected));

    [Test]
    public void Deliveries_survive_the_document_and_replace_one_for_the_same_variable()
    {
        var replaced = Sealed.WithPlaceholder(new("openai_api_key", "llm", "LLM_URL"));

        var back = SealedEnvironment.FromDocument(replaced.ToDocument());

        Assert.That(back.Placeholders, Is.EqualTo(new[] { new EnvironmentPlaceholder("openai_api_key", "llm", "LLM_URL") }));
        Assert.That(back.PlaceholderFor("OPENAI_API_KEY")?.Service, Is.EqualTo("llm"));
        Assert.That(back.WithoutPlaceholder("OPENAI_API_KEY").Placeholders, Is.Empty);
    }

    [Test]
    public void A_document_without_deliveries_reads_as_values_only() =>
        Assert.That(SealedEnvironment.FromDocument(SealedEnvironment.Empty.WithGlobal([new("A", "1")]).ToDocument()).Placeholders, Is.Empty);

    [Test]
    public async Task A_placeholder_variable_gets_a_placeholder_and_the_forwarder_never_the_value()
    {
        var delivery = await EnvironmentDelivery.DeliverAsync(Sealed, Sealed.Global, Forwarder,
            (placeholder, _) => Task.FromResult(new MintedPlaceholder($"tirph_{placeholder.Service}_x")), CancellationToken.None);

        Assert.That(delivery.Variables, Is.EqualTo(new Dictionary<string, string>
        {
            ["OPENAI_API_KEY"] = "tirph_openai_x",
            ["OPENAI_BASE_URL"] = "http://127.0.0.1:7781/svc/openai",
            ["DB_PASSWORD"] = "hunter2",
        }));
        Assert.That(delivery.Problems, Is.Empty);
        Assert.That(EnvironmentDelivery.Placeholders(delivery.Variables.Values), Is.EqualTo(new[] { "tirph_openai_x" }));
    }

    [Test]
    public async Task A_placeholder_that_can_t_be_minted_leaves_the_variable_out_and_says_why()
    {
        var delivery = await EnvironmentDelivery.DeliverAsync(Sealed, Sealed.Global, Forwarder,
            (_, _) => Task.FromResult(new MintedPlaceholder(null, "the solo broker isn't running")), CancellationToken.None);

        Assert.That(delivery.Variables.Keys, Is.EqualTo(new[] { "DB_PASSWORD" }));
        Assert.That(delivery.Problems.Single(), Does.Contain("OPENAI_API_KEY").And.Contain("solo broker").And.Not.Contain("sk-real"));
    }

    [Test]
    public void Consent_lists_a_placeholder_as_one()
    {
        Assert.That(EnvironmentDelivery.Describe(Sealed, "OPENAI_API_KEY"), Is.EqualTo("OPENAI_API_KEY (a placeholder for openai)"));
        Assert.That(EnvironmentDelivery.Describe(Sealed, "DB_PASSWORD"), Is.EqualTo("DB_PASSWORD"));
    }

    [Test]
    public async Task A_terminal_keeps_its_placeholder_until_it_nears_expiry_or_exits()
    {
        var time = new ManualTime(new DateTimeOffset(2026, 11, 18, 8, 0, 0, TimeSpan.Zero));
        var cache = new ShellPlaceholders(time);
        var shell = new ShellIdentity(42, new DateTime(2026, 11, 18, 7, 0, 0, DateTimeKind.Utc), @"C:\pwsh.exe");
        var placeholder = Sealed.Placeholders[0];
        var minted = 0;
        Task<MintedPlaceholder> Mint() => Task.FromResult(new MintedPlaceholder($"tirph_openai_{++minted}"));

        Assert.That((await cache.GetAsync(shell, placeholder, Mint)).Token, Is.EqualTo("tirph_openai_1"));
        time.Now += TimeSpan.FromHours(9);
        Assert.That((await cache.GetAsync(shell, placeholder, Mint)).Token, Is.EqualTo("tirph_openai_1"), "a folder change reuses it");
        time.Now += TimeSpan.FromMinutes(40);
        Assert.That((await cache.GetAsync(shell, placeholder, Mint)).Token, Is.EqualTo("tirph_openai_2"), "close to the 10 h limit it is minted again");

        Assert.That(cache.Release((_, _) => true), Is.EqualTo(new[] { "tirph_openai_1" }), "the replaced one is revoked");
        Assert.That(cache.Release((_, _) => true), Is.Empty);
        Assert.That(cache.Release((id, _) => id != 42), Is.EqualTo(new[] { "tirph_openai_2" }));
        Assert.That(cache.Release((_, _) => false), Is.Empty);
    }

    [Test]
    public async Task A_placeholder_capped_at_the_lease_s_end_is_minted_again_before_then()
    {
        var time = new ManualTime(new DateTimeOffset(2026, 11, 18, 15, 0, 0, TimeSpan.Zero));
        var cache = new ShellPlaceholders(time);
        var shell = new ShellIdentity(7, new DateTime(2026, 11, 18, 14, 0, 0, DateTimeKind.Utc), @"C:\pwsh.exe");
        var minted = 0;
        Task<MintedPlaceholder> Mint() => Task.FromResult(new MintedPlaceholder($"tirph_openai_{++minted}", ExpiresAt: time.Now.AddHours(5)));

        await cache.GetAsync(shell, Sealed.Placeholders[0], Mint);
        time.Now += TimeSpan.FromMinutes(4 * 60 + 40);

        Assert.That((await cache.GetAsync(shell, Sealed.Placeholders[0], Mint)).Token, Is.EqualTo("tirph_openai_2"), "the broker's 20:00, not 01:00");
    }
}
