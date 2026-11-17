using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tiresias.Broker;
using Tiresias.Policy;
using Tiresias.Transport;
using Tiresias.Vault;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace Tiresias.Tests;

/// <summary><c>/token</c> and <c>/placeholder/revoke</c> over HTTP, with GitHub faked.</summary>
public class TokenEndpointTests
{
    string dir = "";
    RSA appKey = null!;
    TestVault vault = null!;
    Key device = null!;
    FakeGitHub github = null!;
    WebApplicationFactory<Program> factory = null!;
    HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        dir = Directory.CreateTempSubdirectory("tir-token-").FullName;
        appKey = RSA.Create(2048);
        var appJson = JsonSerializer.SerializeToUtf8Bytes(new { appId = "4242", installationId = 77L, privateKeyPem = appKey.ExportPkcs8PrivateKeyPem() }, JsonSerializerOptions.Web);
        vault = TestVault.CreateWith(tpm =>
        (
            [SecretEnvelope.Seal("gh-app", 1, appJson, [tpm])],
            [new Service("gh", new Uri("https://api.github.com/"), [new Grant("app", "gh-app", new(new HashSet<string>(), []))])]
        ));
        VaultFile.Save(Path.Combine(dir, "vault.json"), vault.Document);
        device = Key.Create(SignatureAlgorithm.Ed25519);
        github = new FakeGitHub();

        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Broker:VaultPath", Path.Combine(dir, "vault.json"));
            b.UseSetting("Broker:AuditPath", Path.Combine(dir, "audit.jsonl"));
            b.UseSetting("Broker:IdentityKeyPath", Path.Combine(dir, "identity.key"));
            b.UseSetting("Broker:Devices:laptop", Convert.ToBase64String(device.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
            b.ConfigureTestServices(s => s.AddSingleton<IGitHubInstallationTokens>(github));
        });
        client = factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        client.Dispose();
        factory.Dispose();
        device.Dispose();
        vault.Dispose();
        appKey.Dispose();
        TestDirectory.Delete(dir);
    }

    HttpRequestMessage Signed(string endpoint, object? body = null)
    {
        var bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, JsonSerializerOptions.Web);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var message = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new ByteArrayContent(bytes) };
        message.Content.Headers.ContentType = new("application/json");
        message.Headers.Add(RequestSignature.DeviceHeader, "laptop");
        message.Headers.Add(RequestSignature.TimestampHeader, ts.ToString());
        message.Headers.Add(RequestSignature.SignatureHeader, Convert.ToBase64String(RequestSignature.Sign(device, "POST", endpoint, ts, bytes)));
        return message;
    }

    async Task OpenLease()
    {
        var offerJson = await (await client.SendAsync(Signed("/lease/begin"))).Content.ReadFromJsonAsync<JsonElement>();
        var offer = new LeaseOffer(offerJson.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(offerJson.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(offerJson.GetProperty("hardCapAt").GetInt64()));
        await client.SendAsync(Signed("/lease/seal", new { offer.LeaseId, deks = vault.SealTo(offer) }));
    }

    string Audit() => File.ReadAllText(Path.Combine(dir, "audit.jsonl"));

    [Test]
    public async Task A_device_gets_an_installation_token_signed_for_by_the_app_key_which_never_leaves()
    {
        await OpenLease();
        var response = await client.SendAsync(Signed("/token/gh"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(JsonDocument.Parse(body).RootElement.GetProperty("token").GetString(), Is.EqualTo("ghs_fake"));
        Assert.That(body, Does.Not.Contain("PRIVATE KEY"));

        var (api, installation, jwt) = github.Calls.Single();
        Assert.That(api, Is.EqualTo(new Uri("https://api.github.com/")));
        Assert.That(installation, Is.EqualTo(77));
        var parts = jwt.Split('.');
        Assert.That(appKey.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
            Convert.FromBase64String(parts[2].Replace('-', '+').Replace('_', '/').PadRight(parts[2].Length + (4 - parts[2].Length % 4) % 4, '=')),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);
        Assert.That(Audit(), Does.Contain("\"kind\":\"Token\"").And.Not.Contain("ghs_fake"));
    }

    [Test]
    public async Task A_token_needs_a_device_signature_and_a_lease()
    {
        Assert.That((await client.PostAsync("/token/gh", null)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That((await client.SendAsync(Signed("/token/gh"))).StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
        Assert.That(github.Calls, Is.Empty);
    }

    [Test]
    public async Task Only_a_github_service_issues_tokens()
    {
        await OpenLease();
        var response = await client.SendAsync(Signed("/token/llm"));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(github.Calls, Is.Empty);
    }

    [Test]
    public async Task A_github_refusal_is_a_502()
    {
        await OpenLease();
        github.Refuse = true;
        Assert.That((await client.SendAsync(Signed("/token/gh"))).StatusCode, Is.EqualTo(HttpStatusCode.BadGateway));
    }

    [Test]
    public async Task A_revoked_placeholder_stops_working_at_once()
    {
        await OpenLease();
        var mint = await client.SendAsync(Signed("/placeholder", new { consumer = "exec:tool", serviceSlug = "llm", purpose = "testing", duration = "01:00:00" }));
        var token = (await mint.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;

        Assert.That((await client.SendAsync(Signed("/placeholder/revoke", new { token }))).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));

        var use = new HttpRequestMessage(HttpMethod.Get, "/svc/llm/v1/models");
        use.Headers.Authorization = new("Bearer", token);
        var response = await client.SendAsync(use);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(Audit(), Does.Contain("\"kind\":\"PlaceholderRevoked\""));
    }

    sealed class FakeGitHub : IGitHubInstallationTokens
    {
        public List<(Uri Api, long InstallationId, string Jwt)> Calls { get; } = [];
        public bool Refuse { get; set; }

        public Task<InstallationToken?> CreateAsync(Uri api, long installationId, string appJwt, CancellationToken ct)
        {
            Calls.Add((api, installationId, appJwt));
            return Task.FromResult(Refuse ? null : new InstallationToken("ghs_fake", DateTimeOffset.UtcNow.AddHours(1)));
        }
    }
}
