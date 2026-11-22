using System.Text.Json.Nodes;
using Tiresias.EnvironmentVariables;
using Tiresias.UserSecrets;

namespace Tiresias.Tests;

/// <summary>Which NuGet requests a sealed mapping answers, and the plugin protocol NuGet speaks to the plugin.</summary>
public class NuGetCredentialTests
{
    const string Feed = "https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json";

    static readonly SealedEnvironment Mapped = SealedEnvironment.Empty
        .WithGlobal([new("AZDO_PAT", "pat")])
        .WithNuGetSource(new(Feed, "AZDO_PAT", SealedEnvironment.NuGetDefaultUsername));

    [TestCase(Feed, true)]
    [TestCase("https://PKGS.dev.azure.com:443/example/_packaging/shop/nuget/v3/index.json", true)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json/", false)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/other-index.json", false)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/flat2/newtonsoft.json/index.json", false)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json?view=preview", false)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json#preview", false)]
    [TestCase("https://reader@pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json", false)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/Shop/nuget/v3/index.json", false)]
    [TestCase("https://pkgs.dev.azure.com:8443/example/_packaging/shop/nuget/v3/index.json", false)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/other/nuget/v3/index.json", false)]
    [TestCase("http://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json", false)]
    [TestCase("https://pkgs.dev.azure.com.example.net/example/_packaging/shop/nuget/v3/index.json", false)]
    [TestCase("https://api.nuget.org/v3/index.json", false)]
    public void Credentials_are_available_only_for_the_configured_package_source(string uri, bool answered) =>
        Assert.That(Mapped.NuGetSourceFor(new Uri(uri))?.Variable, answered ? Is.EqualTo("AZDO_PAT") : Is.Null);

    [Test]
    public void Feed_paths_remain_distinct_and_duplicate_mappings_cannot_choose_a_credential()
    {
        var lower = new NuGetSource("https://feeds.example/shop/long-service-index.json", "LOWER", "reader");
        var upper = lower with { Source = "https://feeds.example/Shop/long-service-index.json", Variable = "UPPER" };
        var feeds = SealedEnvironment.Empty.WithNuGetSource(lower).WithNuGetSource(upper);

        Assert.That(feeds.NuGetSourceFor(new Uri(upper.Source)), Is.EqualTo(upper));
        Assert.That(feeds.NuGetSourceFor(new Uri(lower.Source)), Is.EqualTo(lower));
        Assert.That(feeds.WithoutNuGetSource(upper.Source).NuGetSourceFor(new Uri(lower.Source)), Is.EqualTo(lower));
        var duplicate = lower with { Source = lower.Source.Replace("feeds.example", "FEEDS.example", StringComparison.Ordinal), Variable = "OTHER" };
        Assert.That((feeds with { NuGetSources = [lower, duplicate] }).NuGetSourceFor(new Uri(lower.Source)), Is.Null);
    }

    [Test]
    public async Task A_session_approval_covers_only_the_shown_feed_account_and_variable_for_its_program()
    {
        var consent = new NuGetConsent();
        var source = new NuGetSource(Feed, "TOKEN", "reader");
        int prompts = 0;
        async Task<NuGetOutcome> Request(string program, NuGetSource mapping, ConsentAnswer answer)
        {
            var (outcome, _) = await consent.DecideAsync(program, mapping, default, () =>
            {
                prompts++;
                return Task.FromResult(answer);
            }, () => Task.FromResult(default(ReleasePolicy)), () => { });
            return outcome;
        }

        Assert.That(await Request("dotnet", source, ConsentAnswer.AllowForSession), Is.EqualTo(NuGetOutcome.AllowedForSession));
        Assert.That(await Request("dotnet", source, ConsentAnswer.Deny), Is.EqualTo(NuGetOutcome.CoveredBySession));
        Assert.That(await Request("dotnet", source with { Source = "https://feeds.example/other" }, ConsentAnswer.Deny), Is.EqualTo(NuGetOutcome.Denied));
        Assert.That(await Request("dotnet", source with { Username = "owner" }, ConsentAnswer.Deny), Is.EqualTo(NuGetOutcome.Denied));
        Assert.That(await Request("dotnet", source with { Variable = "OTHER" }, ConsentAnswer.Deny), Is.EqualTo(NuGetOutcome.Denied));
        Assert.That(await Request("IDE", source, ConsentAnswer.AllowOnce), Is.EqualTo(NuGetOutcome.AllowedOnce));
        Assert.That(await Request("IDE", source, ConsentAnswer.Deny), Is.EqualTo(NuGetOutcome.Denied));
        Assert.That(prompts, Is.EqualTo(6));
    }

    [Test]
    public async Task A_caller_without_a_feed_can_approve_each_request_once()
    {
        var consent = new NuGetConsent();
        Task<(NuGetOutcome Outcome, string? PolicyRefusal)> Request(ConsentAnswer answer) =>
            consent.DecideAsync("dotnet", "TOKEN", default, () => Task.FromResult(answer), () => Task.FromResult(default(ReleasePolicy)));

        Assert.That((await Request(ConsentAnswer.AllowForSession)).Outcome, Is.EqualTo(NuGetOutcome.AllowedOnce));
        Assert.That((await Request(ConsentAnswer.Deny)).Outcome, Is.EqualTo(NuGetOutcome.Denied));
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task Restoring_a_feed_or_its_variable_requires_a_new_approval(bool removeVariable)
    {
        var consent = new NuGetConsent();
        var uri = new Uri(Feed);
        var source = consent.Match(Mapped, uri)!;
        Task<(NuGetOutcome, string?)> Request(ConsentAnswer answer) => consent.DecideAsync("dotnet", source, default,
            () => Task.FromResult(answer), () => Task.FromResult(default(ReleasePolicy)), () => { });

        Assert.That((await Request(ConsentAnswer.AllowForSession)).Item1, Is.EqualTo(NuGetOutcome.AllowedForSession));
        consent.Match(removeVariable ? Mapped.WithoutGlobal([source.Variable]) : Mapped.WithoutNuGetSource(Feed), uri);
        Assert.That(consent.Match(Mapped, uri), Is.EqualTo(source));
        Assert.That((await Request(ConsentAnswer.Deny)).Item1, Is.EqualTo(NuGetOutcome.Denied));
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task Both_new_and_remembered_grants_check_the_current_environment_before_delivery(bool remembered)
    {
        var consent = new NuGetConsent();
        var source = new NuGetSource(Feed, "TOKEN", "reader");
        var prompts = 0;
        Task<(NuGetOutcome, string?)> Request(Action validate) => consent.DecideAsync("dotnet", source, default, () =>
        {
            prompts++;
            return Task.FromResult(ConsentAnswer.AllowForSession);
        }, () => Task.FromResult(default(ReleasePolicy)), validate);

        if (remembered)
            await Request(() => { });
        Assert.ThrowsAsync<InvalidDataException>(async () => await Request(() => throw new InvalidDataException("Environment changed.")));
        Assert.That(prompts, Is.EqualTo(1));
        if (!remembered)
        {
            var (outcome, _) = await Request(() => { });
            Assert.That(outcome, Is.EqualTo(NuGetOutcome.AllowedForSession));
            Assert.That(prompts, Is.EqualTo(2));
        }
    }

    [Test]
    public async Task Clearing_consent_while_a_prompt_is_open_withholds_the_credential_and_the_grant()
    {
        var consent = new NuGetConsent();
        var source = Mapped.NuGetSources.Single();
        var (outcome, refusal) = await consent.DecideAsync("dotnet", source, default, () =>
        {
            consent.Clear();
            return Task.FromResult(ConsentAnswer.AllowForSession);
        }, () => Task.FromResult(default(ReleasePolicy)), () => { });
        Assert.That(outcome, Is.EqualTo(NuGetOutcome.Denied));
        Assert.That(refusal, Is.Not.Null);

        var next = await consent.DecideAsync("dotnet", source, default, () => Task.FromResult(ConsentAnswer.Deny),
            () => Task.FromResult(default(ReleasePolicy)), () => { });
        Assert.That(next.Outcome, Is.EqualTo(NuGetOutcome.Denied));
    }

    [Test]
    public void Mappings_survive_the_document_and_replace_one_for_the_same_source()
    {
        var source = new NuGetSource(Feed.Replace("pkgs.dev.azure.com", "PKGS.dev.azure.com:443", StringComparison.Ordinal), "OTHER_PAT", "alice");
        var replaced = Mapped.WithNuGetSource(source);

        var back = SealedEnvironment.FromDocument(replaced.ToDocument());

        Assert.That(back.NuGetSources, Is.EqualTo(new[] { source }));
        Assert.That(back.WithoutNuGetSource(Feed).NuGetSources, Is.Empty);
    }

    [Test]
    public async Task The_plugin_shakes_hands_claims_authentication_and_answers_with_the_lookup()
    {
        var replies = await ConverseAsync((uri, retry, _) => Task.FromResult(new NuGetCredential("tiresias", $"pat for {uri.Host}")),
            Request("1", "Handshake", new() { ["ProtocolVersion"] = "2.0.0", ["MinimumProtocolVersion"] = "1.0.0" }),
            Request("2", "GetOperationClaims", new() { ["PackageSourceRepository"] = Feed }),
            Request("3", "GetAuthenticationCredentials", new() { ["Uri"] = Feed, ["IsRetry"] = false }),
            Request("4", "Close", []));

        Assert.That((string?)replies[0]["Method"], Is.EqualTo("Handshake"), "the plugin's own handshake goes first");
        Assert.That((string?)replies[0]["Type"], Is.EqualTo("Request"));
        Assert.That((string?)Answer(replies, "1")["ResponseCode"], Is.EqualTo("Success"));
        Assert.That(Answer(replies, "2")["Claims"]!.AsArray().Select(c => (string?)c), Is.EqualTo(new[] { "Authentication" }));
        var credential = Answer(replies, "3");
        Assert.That((string?)credential["Username"], Is.EqualTo("tiresias"));
        Assert.That((string?)credential["Password"], Is.EqualTo("pat for pkgs.dev.azure.com"));
        Assert.That(replies.Any(r => (string?)r["RequestId"] == "4"), Is.False, "Close is not answered");
    }

    [Test]
    public async Task No_credential_is_NotFound_so_NuGet_tries_its_other_providers()
    {
        var replies = await ConverseAsync((_, _, _) => Task.FromResult(new NuGetCredential(null, null, "not mapped")),
            Request("1", "GetAuthenticationCredentials", new() { ["Uri"] = Feed, ["IsRetry"] = true }),
            Request("2", "GetPackageVersions", []));

        Assert.That((string?)Answer(replies, "1")["ResponseCode"], Is.EqualTo("NotFound"));
        Assert.That(Answer(replies, "1").ContainsKey("Password"), Is.False);
        Assert.That((string?)Answer(replies, "2")["ResponseCode"], Is.EqualTo("NotFound"));
    }

    [Test]
    public async Task A_slow_answer_sends_progress_so_NuGet_keeps_waiting()
    {
        var replies = await ConverseAsync(async (_, _, ct) =>
            {
                await Task.Delay(TimeSpan.FromSeconds(2.5), ct);
                return new NuGetCredential("u", "p");
            },
            Request("1", "GetAuthenticationCredentials", new() { ["Uri"] = Feed }));

        Assert.That(replies.Count(r => (string?)r["Type"] == "Progress" && (string?)r["RequestId"] == "1"), Is.GreaterThanOrEqualTo(1));
        Assert.That((string?)Answer(replies, "1")["Password"], Is.EqualTo("p"));
    }

    static JsonObject Request(string id, string method, JsonObject payload) =>
        new() { ["RequestId"] = id, ["Type"] = "Request", ["Method"] = method, ["Payload"] = payload };

    static JsonObject Answer(IEnumerable<JsonObject> replies, string id) =>
        (JsonObject)replies.Single(r => (string?)r["RequestId"] == id && (string?)r["Type"] == "Response")["Payload"]!;

    static async Task<List<JsonObject>> ConverseAsync(Func<Uri, bool, CancellationToken, Task<NuGetCredential>> lookup, params JsonObject[] requests)
    {
        var input = new StringReader(string.Join('\n', requests.Select(r => r.ToJsonString())) + "\n");
        var output = new StringWriter();
        await new NuGetCredentialPlugin(input, output, lookup).RunAsync(CancellationToken.None);
        return [.. output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(l => (JsonObject)JsonNode.Parse(l)!)];
    }
}
