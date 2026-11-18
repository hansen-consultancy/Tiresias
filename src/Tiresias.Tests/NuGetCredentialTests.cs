using System.Text.Json.Nodes;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

/// <summary>Which NuGet requests a sealed mapping answers, and the plugin protocol NuGet speaks to the plugin.</summary>
public class NuGetCredentialTests
{
    const string Feed = "https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json";

    static readonly SealedEnvironment Mapped = SealedEnvironment.Empty
        .WithGlobal([new("AZDO_PAT", "pat")])
        .WithNuGetSource(new(Feed, "AZDO_PAT", SealedEnvironment.NuGetDefaultUsername));

    [TestCase(Feed, true)]
    [TestCase("https://PKGS.dev.azure.com/example/_packaging/shop/nuget/v3/index.json/", true)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/flat2/newtonsoft.json/index.json", true)]
    [TestCase("https://pkgs.dev.azure.com/example/_packaging/other/nuget/v3/index.json", false)]
    [TestCase("http://pkgs.dev.azure.com/example/_packaging/shop/nuget/v3/index.json", false)]
    [TestCase("https://pkgs.dev.azure.com.example.net/example/_packaging/shop/nuget/v3/index.json", false)]
    [TestCase("https://api.nuget.org/v3/index.json", false)]
    public void A_request_is_answered_for_the_source_and_what_its_folder_serves_on_the_same_https_host(string uri, bool answered) =>
        Assert.That(Mapped.NuGetSourceFor(new Uri(uri))?.Variable, answered ? Is.EqualTo("AZDO_PAT") : Is.Null);

    [Test]
    public void Mappings_survive_the_document_and_replace_one_for_the_same_source()
    {
        var replaced = Mapped.WithNuGetSource(new(Feed + "/", "OTHER_PAT", "alice"));

        var back = SealedEnvironment.FromDocument(replaced.ToDocument());

        Assert.That(back.NuGetSources, Is.EqualTo(new[] { new NuGetSource(Feed + "/", "OTHER_PAT", "alice") }));
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
