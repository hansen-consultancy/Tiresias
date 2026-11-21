using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Tiresias.Audit;
using Tiresias.Broker;
using Tiresias.Transport;
using Tiresias.Vault;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace Tiresias.Tests;

/// <summary>The broker over HTTP, with a fake upstream behind the named client.</summary>
public class BrokerHostTests
{
    string dir = "";
    TestVault vault = null!;
    Key device = null!;
    FakeUpstream upstream = null!;
    WebApplicationFactory<Program> factory = null!;
    WebApplicationFactory<Program>? parent;
    HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        dir = Directory.CreateTempSubdirectory("tir-host-").FullName;
        vault = TestVault.Create();
        VaultFile.Save(Path.Combine(dir, "vault.json"), vault.Document);
        device = Key.Create(SignatureAlgorithm.Ed25519);
        upstream = new FakeUpstream();

        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Broker:VaultPath", Path.Combine(dir, "vault.json"));
            b.UseSetting("Broker:AuditPath", Path.Combine(dir, "audit.jsonl"));
            b.UseSetting("Broker:IdentityKeyPath", Path.Combine(dir, "identity.key"));
            b.UseSetting("Broker:Devices:laptop", Convert.ToBase64String(device.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
            b.ConfigureTestServices(s => s.AddHttpClient(SvcProxy.ClientName).ConfigurePrimaryHttpMessageHandler(() => upstream));
        });
        client = factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        client.Dispose();
        factory.Dispose();
        parent?.Dispose();
        parent = null;
        upstream.Dispose();
        device.Dispose();
        vault.Dispose();
        TestDirectory.Delete(dir);
    }

    HttpRequestMessage Signed(string endpoint, object? body = null, string signedEndpoint = "")
    {
        var bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, JsonSerializerOptions.Web);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var message = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new ByteArrayContent(bytes) };
        message.Content.Headers.ContentType = new("application/json");
        message.Headers.Add(RequestSignature.DeviceHeader, "laptop");
        message.Headers.Add(RequestSignature.TimestampHeader, ts.ToString(System.Globalization.CultureInfo.InvariantCulture));
        message.Headers.Add(RequestSignature.SignatureHeader,
            Convert.ToBase64String(RequestSignature.Sign(device, "POST", signedEndpoint is "" ? endpoint : signedEndpoint, ts, bytes)));
        return message;
    }

    async Task<string> OpenLeaseAndMint(string? ceiling = null)
    {
        var begin = await client.SendAsync(Signed("/lease/begin"));
        Assert.That(begin.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var offerJson = await begin.Content.ReadFromJsonAsync<JsonElement>();
        var offer = new LeaseOffer(
            offerJson.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(offerJson.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(offerJson.GetProperty("hardCapAt").GetInt64()));

        // The Keyring checks the offer against the identity it pinned.
        var raw = factory.Services.GetRequiredService<IIdentityKeyStore>().Load()!;
        using (var identity = Key.Import(SignatureAlgorithm.Ed25519, raw, KeyBlobFormat.RawPrivateKey))
            Assert.That(offer.Verify(identity.PublicKey, Convert.FromBase64String(offerJson.GetProperty("signature").GetString()!)), Is.True);

        var seal = await client.SendAsync(Signed("/lease/seal", vault.SealBody(offer)));
        Assert.That(seal.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var mint = await client.SendAsync(Signed("/placeholder",
            vault.MintApproval(new("claude:test", null, "llm", ceiling, "testing", TimeSpan.FromHours(1)))));
        Assert.That(mint.StatusCode, Is.EqualTo(HttpStatusCode.OK), await mint.Content.ReadAsStringAsync());
        return (await mint.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
    }

    HttpRequestMessage Svc(HttpMethod method, string path, string token)
    {
        var message = new HttpRequestMessage(method, path);
        message.Headers.Authorization = new("Bearer", token);
        message.Headers.Add("X-Tiresias-Device", "laptop");
        message.Headers.Add("X-Trace", "t-1");
        return message;
    }

    [Test]
    public async Task An_unsigned_management_request_is_unauthorized() =>
        Assert.That((await client.PostAsync("/lease/begin", null)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task A_signature_for_another_endpoint_is_unauthorized() =>
        Assert.That((await client.SendAsync(Signed("/lease/begin", signedEndpoint: "/lease/end"))).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task A_replayed_signature_is_unauthorized()
    {
        var first = Signed("/lease/end");
        var replay = new HttpRequestMessage(HttpMethod.Post, "/lease/end") { Content = new ByteArrayContent([]) };
        foreach (var h in first.Headers)
            replay.Headers.Add(h.Key, h.Value);

        Assert.That((await client.SendAsync(first)).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
        Assert.That((await client.SendAsync(replay)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Without_a_lease_svc_answers_503_and_never_calls_upstream()
    {
        var response = await client.SendAsync(Svc(HttpMethod.Get, "/svc/llm/v1/models", "tirph_llm_whatever"));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reason").GetString(), Is.EqualTo("no-lease"));
        Assert.That(upstream.Requests, Is.Empty);
    }

    [Test]
    public async Task An_allowed_request_reaches_upstream_with_the_real_credential_only()
    {
        var token = await OpenLeaseAndMint();
        var response = await client.SendAsync(Svc(HttpMethod.Get, "/svc/llm/v1/models?page=2", token));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo("upstream-body"));
        Assert.That(response.Headers.GetValues("X-Upstream"), Is.EqualTo(new[] { "yes" }));

        var seen = upstream.Requests.Single();
        Assert.That(seen.Uri, Is.EqualTo("https://llm.example/v1/models?page=2"));
        Assert.That(seen.Headers["Authorization"], Is.EqualTo("Bearer sk-read"));
        Assert.That(seen.Headers["X-Trace"], Is.EqualTo("t-1"));
        Assert.That(seen.Headers.Keys, Has.None.StartsWith("X-Tiresias-"));
        Assert.That(string.Join("\n", seen.Headers.Values), Does.Not.Contain(token));
        Assert.That(AuditLog.Verify(Path.Combine(dir, "audit.jsonl")), Is.Null);
    }

    [Test]
    public async Task The_observed_process_is_audited_and_not_sent_upstream()
    {
        var token = await OpenLeaseAndMint();
        var message = Svc(HttpMethod.Get, "/svc/llm/v1/models", token);
        message.Headers.Add(ForwarderHeaders.ObservedProcess, @"C:\tools\export.exe (pid 4242)");
        Assert.That((await client.SendAsync(message)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        Assert.That(upstream.Requests.Single().Headers.Keys, Has.None.StartsWith("X-Tiresias-"));
        var allow = File.ReadLines(Path.Combine(dir, "audit.jsonl"))
            .Select(l => JsonDocument.Parse(l).RootElement)
            .Single(r => r.GetProperty("kind").GetString() == "Allow");
        Assert.That(allow.GetProperty("process").GetString(), Is.EqualTo(@"C:\tools\export.exe (pid 4242)"));
    }

    [Test]
    public async Task In_solo_mode_a_caller_cannot_claim_a_process_of_its_own()
    {
        parent = factory;
        client.Dispose();
        factory = parent.WithWebHostBuilder(b => b.UseSetting("Broker:IdentifyLoopbackCaller", "true"));
        client = factory.CreateClient();

        var token = await OpenLeaseAndMint();
        var message = Svc(HttpMethod.Get, "/svc/llm/v1/models", token);
        message.Headers.Add(ForwarderHeaders.ObservedProcess, @"C:\tools\innocent.exe (pid 1)");
        Assert.That((await client.SendAsync(message)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        // The test server has no loopback connection to look up, so nothing is recorded: never the claim.
        var allow = File.ReadLines(Path.Combine(dir, "audit.jsonl"))
            .Select(l => JsonDocument.Parse(l).RootElement)
            .Single(r => r.GetProperty("kind").GetString() == "Allow");
        Assert.That(allow.TryGetProperty("process", out var process) ? process.GetString() : null, Is.Null);
    }

    [Test]
    public async Task A_post_body_is_forwarded_under_the_write_grant()
    {
        var token = await OpenLeaseAndMint();
        var message = Svc(HttpMethod.Post, "/svc/llm/v1/chat", token);
        message.Content = new StringContent("""{"q":1}""", Encoding.UTF8, "application/json");
        var response = await client.SendAsync(message);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var seen = upstream.Requests.Single();
        Assert.That(seen.Headers["Authorization"], Is.EqualTo("Bearer sk-write"));
        Assert.That(seen.Body, Is.EqualTo("""{"q":1}"""));
    }

    [Test]
    public async Task A_denied_request_is_403_with_the_reason_and_never_calls_upstream()
    {
        var token = await OpenLeaseAndMint(ceiling: "read");
        var message = Svc(HttpMethod.Post, "/svc/llm/v1/chat", token);
        message.Content = new StringContent("{}");
        var response = await client.SendAsync(message);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reason").GetString(), Is.EqualTo("not-covered"));
        Assert.That(upstream.Requests, Is.Empty);
    }

    [Test]
    public async Task An_elevation_denial_names_the_grant_and_elevate_unlocks_it()
    {
        var token = await OpenLeaseAndMint();
        var denied = await client.SendAsync(Svc(HttpMethod.Delete, "/svc/llm/v1/models/x", token));
        Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That((await denied.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("elevationNeeded").GetString(), Is.EqualTo("admin"));

        var elevate = await client.SendAsync(Signed("/elevate", vault.ElevateApproval("llm", "admin", TimeSpan.FromMinutes(5))));
        Assert.That(elevate.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var allowed = await client.SendAsync(Svc(HttpMethod.Delete, "/svc/llm/v1/models/x", token));
        Assert.That(allowed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(upstream.Requests.Single().Headers["Authorization"], Is.EqualTo("Bearer sk-admin"));
    }

    [Test]
    public async Task An_encoded_slash_is_refused_not_normalised()
    {
        var token = await OpenLeaseAndMint();
        var response = await client.SendAsync(Svc(HttpMethod.Get, "/svc/llm/v1/models%2f..%2fadmin", token));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reason").GetString(), Is.EqualTo("suspicious-path"));
        Assert.That(upstream.Requests, Is.Empty);
    }

    [Test]
    public async Task Ending_the_lease_makes_the_placeholder_useless()
    {
        var token = await OpenLeaseAndMint();
        Assert.That((await client.SendAsync(Signed("/lease/end"))).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
        var response = await client.SendAsync(Svc(HttpMethod.Get, "/svc/llm/v1/models", token));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
        Assert.That(upstream.Requests, Is.Empty);
    }

    sealed record SeenRequest(string Uri, Dictionary<string, string> Headers, string Body);

    sealed class FakeUpstream : HttpMessageHandler
    {
        public List<SeenRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var headers = request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
                .ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new(request.RequestUri!.OriginalString, headers, body));

            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("upstream-body") };
            response.Headers.Add("X-Upstream", "yes");
            return response;
        }
    }
}
