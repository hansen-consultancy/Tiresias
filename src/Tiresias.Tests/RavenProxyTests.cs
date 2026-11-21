using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Tiresias.Broker;
using Tiresias.Raven;
using Tiresias.Transport;
using Tiresias.Vault;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class RavenTopologyTests
{
    const string Base = "http://127.0.0.1:7781/raven/prod";

    [TestCase("/topology?name=Orders", true)]
    [TestCase("/cluster/topology", true)]
    [TestCase("/topology", true)]
    [TestCase("/databases/Orders/topology", false)]
    [TestCase("/databases/Orders/docs?id=topology", false)]
    [TestCase("/cluster/topology/extra", false)]
    public void Only_the_two_topology_endpoints_are_rewritten(string path, bool expected) =>
        Assert.That(RavenTopology.IsTopologyPath(path), Is.EqualTo(expected));

    [Test]
    public void Every_database_topology_node_url_points_at_the_proxy()
    {
        var json = """{"Nodes":[{"Url":"https://a.raven.example","ClusterTag":"A","Database":"Orders","ServerRole":"Member"},{"Url":"https://b.raven.example","ClusterTag":"B"}],"Etag":12}""";
        using var rewritten = JsonDocument.Parse(RavenTopology.Rewrite(json, Base));
        var nodes = rewritten.RootElement.GetProperty("Nodes");
        Assert.That(nodes.EnumerateArray().Select(n => n.GetProperty("Url").GetString()), Is.EqualTo(new[] { Base, Base }));
        Assert.That(nodes[0].GetProperty("ClusterTag").GetString(), Is.EqualTo("A"));
        Assert.That(rewritten.RootElement.GetProperty("Etag").GetInt32(), Is.EqualTo(12));
    }

    [Test]
    public void Every_cluster_topology_node_map_points_at_the_proxy()
    {
        var json = """
            {"Topology":{"TopologyId":"t","AllNodes":{"A":"https://a.raven.example","B":"https://b.raven.example"},
             "Members":{"A":"https://a.raven.example"},"Promotables":{"B":"https://b.raven.example"},"Watchers":{},"Etag":3},
             "Leader":"A","NodeTag":"A","Status":{"A":{"Name":"https://a.raven.example"}}}
            """;
        using var rewritten = JsonDocument.Parse(RavenTopology.Rewrite(json, Base));
        var topology = rewritten.RootElement.GetProperty("Topology");
        foreach (var map in new[] { "AllNodes", "Members", "Promotables" })
            Assert.That(topology.GetProperty(map).EnumerateObject().Select(p => p.Value.GetString()), Is.All.EqualTo(Base), map);
        Assert.That(topology.GetProperty("TopologyId").GetString(), Is.EqualTo("t"));
        Assert.That(rewritten.RootElement.GetProperty("Leader").GetString(), Is.EqualTo("A"), "tags are not URLs");
        Assert.That(rewritten.RootElement.GetProperty("Status").GetProperty("A").GetProperty("Name").GetString(),
            Is.EqualTo("https://a.raven.example"), "only Url properties and the node maps are touched");
    }

    [Test]
    public void A_body_that_is_not_json_is_returned_unchanged() =>
        Assert.That(RavenTopology.Rewrite("<html>maintenance</html>", Base), Is.EqualTo("<html>maintenance</html>"));
}

public class RavenPathTests
{
    [TestCase("/tirph_db_abc/databases/Orders/docs?id=1", "tirph_db_abc", "/databases/Orders/docs?id=1")]
    [TestCase("/tirph_db_abc?x=1", "tirph_db_abc", "/?x=1")]
    [TestCase("/tirph_db_abc", "tirph_db_abc", "/")]
    [TestCase("/tirph_db_abc/", "tirph_db_abc", "/")]
    [TestCase("/databases/Orders/docs", null, "/databases/Orders/docs")]
    [TestCase("/databases/tirph_x/docs", null, "/databases/tirph_x/docs")]
    [TestCase("/", null, "/")]
    public void A_placeholder_is_only_ever_the_first_segment(string remainder, string? placeholder, string rest) =>
        Assert.That(RavenPath.Split(remainder), Is.EqualTo((placeholder, rest)));
}

/// <summary><c>/raven</c> over HTTP, with a fake TLS stack that records which certificate it was given.</summary>
public class RavenProxyTests
{
    string dir = "";
    X509Certificate2 issued = null!;
    TestVault vault = null!;
    Key device = null!;
    FakeRaven raven = null!;
    WebApplicationFactory<Program> factory = null!;
    HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        var changes = TestContext.CurrentContext.Test.Properties["Category"].Contains("changes");
        dir = Directory.CreateTempSubdirectory("tir-raven-").FullName;
        using (var rsa = RSA.Create(2048))
        {
            var request = new CertificateRequest("CN=tir-test-client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        }
        vault = TestVault.CreateWithRaven(issued.Export(X509ContentType.Pfx), changes);
        VaultFile.Save(Path.Combine(dir, "vault.json"), vault.Document);
        device = Key.Create(SignatureAlgorithm.Ed25519);
        raven = new FakeRaven();

        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Broker:VaultPath", Path.Combine(dir, "vault.json"));
            b.UseSetting("Broker:AuditPath", Path.Combine(dir, "audit.jsonl"));
            b.UseSetting("Broker:IdentityKeyPath", Path.Combine(dir, "identity.key"));
            b.UseSetting("Broker:Devices:laptop", Convert.ToBase64String(device.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
            b.ConfigureTestServices(s => s.AddSingleton<RavenHandlerFactory>(raven.Handler));
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
        issued.Dispose();
        TestDirectory.Delete(dir);
    }

    HttpRequestMessage Signed(string endpoint, object? body = null)
    {
        var bytes = body is null ? [] : JsonSerializer.SerializeToUtf8Bytes(body, JsonSerializerOptions.Web);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var message = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new ByteArrayContent(bytes) };
        message.Content.Headers.ContentType = new("application/json");
        message.Headers.Add(RequestSignature.DeviceHeader, "laptop");
        message.Headers.Add(RequestSignature.TimestampHeader, ts.ToString(System.Globalization.CultureInfo.InvariantCulture));
        message.Headers.Add(RequestSignature.SignatureHeader, Convert.ToBase64String(RequestSignature.Sign(device, "POST", endpoint, ts, bytes)));
        return message;
    }

    async Task<string> OpenLeaseAndMint()
    {
        var offerJson = await (await client.SendAsync(Signed("/lease/begin"))).Content.ReadFromJsonAsync<JsonElement>();
        var offer = new LeaseOffer(offerJson.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(offerJson.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(offerJson.GetProperty("hardCapAt").GetInt64()));
        await client.SendAsync(Signed("/lease/seal", vault.SealBody(offer)));
        var mint = await client.SendAsync(Signed("/placeholder",
            vault.MintApproval(new("claude:test", null, "ravendb", null, "testing", TimeSpan.FromHours(1)))));
        return (await mint.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
    }

    Task<HttpResponseMessage> Get(string path, string? token, string? publicBase = null)
    {
        var message = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
            message.Headers.Authorization = new("Bearer", token);
        message.Headers.Add("Accept-Encoding", "gzip");
        if (publicBase is not null)
            message.Headers.Add(ForwarderHeaders.PublicBase, publicBase);
        return client.SendAsync(message);
    }

    [Test]
    public async Task A_request_reaches_the_node_with_the_vault_certificate_and_without_the_placeholder()
    {
        var token = await OpenLeaseAndMint();
        var response = await Get("/raven/ravendb/databases/Orders/docs?id=orders/1", token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var seen = raven.Requests.Single();
        Assert.That(seen.Uri, Is.EqualTo("https://a.raven.example/databases/Orders/docs?id=orders/1"));
        Assert.That(seen.Authorization, Is.Null);
        Assert.That(raven.Certificates.Single().Thumbprint, Is.EqualTo(issued.Thumbprint));
        Assert.That(raven.Certificates.Single().HasPrivateKey, Is.True);
    }

    [Test]
    public async Task The_topology_comes_back_pointing_at_the_broker_uncompressed()
    {
        var token = await OpenLeaseAndMint();
        var response = await Get("/raven/ravendb/topology?name=Orders", token);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(body.GetProperty("Nodes")[0].GetProperty("Url").GetString(), Is.EqualTo("http://localhost/raven/ravendb"));
        Assert.That(raven.Requests.Single().AcceptEncoding, Is.Null);
    }

    [TestCase("http://127.0.0.1:7781", "http://127.0.0.1:7781/raven/ravendb")]
    [TestCase("http://evil.example:7781", "http://localhost/raven/ravendb")]
    public async Task Only_a_loopback_forwarder_origin_is_used_as_the_topology_base(string publicBase, string expected)
    {
        var token = await OpenLeaseAndMint();
        var response = await Get("/raven/ravendb/cluster/topology", token, publicBase);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(body.GetProperty("Topology").GetProperty("AllNodes").GetProperty("A").GetString(), Is.EqualTo(expected));
    }

    [Test]
    public async Task The_certificate_is_loaded_once_per_lease_and_disposed_when_it_ends()
    {
        var token = await OpenLeaseAndMint();
        await Get("/raven/ravendb/databases/Orders/stats", token);
        await Get("/raven/ravendb/databases/Orders/stats", token);
        Assert.That(raven.Certificates, Has.Count.EqualTo(1));
        var certificate = raven.Certificates.Single();

        await client.SendAsync(Signed("/lease/end"));

        var disposed = SpinWait.SpinUntil(() => certificate.Handle == IntPtr.Zero, TimeSpan.FromSeconds(5));
        Assert.That(disposed, Is.True, "the in-memory certificate dies with the lease");
    }

    [Test]
    public async Task Without_a_placeholder_nothing_reaches_the_node()
    {
        await OpenLeaseAndMint();
        var response = await client.GetAsync("/raven/ravendb/databases/Orders/stats");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(raven.Requests, Is.Empty);
    }

    /// <summary>The audit so far, read beside the broker, which keeps the file open.</summary>
    string Audit()
    {
        using var stream = new FileStream(Path.Combine(dir, "audit.jsonl"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return new StreamReader(stream).ReadToEnd();
    }

    [Test]
    public async Task A_placeholder_in_the_path_stands_in_for_the_header_and_never_reaches_the_node()
    {
        var token = await OpenLeaseAndMint();
        var response = await Get($"/raven/ravendb/{token}/databases/Orders/docs?id=orders/1", token: null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var seen = raven.Requests.Single();
        Assert.That(seen.Uri, Is.EqualTo("https://a.raven.example/databases/Orders/docs?id=orders/1"));
        Assert.That(seen.Authorization, Is.Null);
        Assert.That(Audit(), Does.Not.Contain(token), "the audit keeps a hash of the placeholder, never the placeholder");
    }

    [Test]
    public async Task With_the_placeholder_in_the_path_the_topology_keeps_it_in_every_node_url()
    {
        var token = await OpenLeaseAndMint();
        var response = await Get($"/raven/ravendb/{token}/topology?name=Orders", token: null, "http://127.0.0.1:7781");

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(body.GetProperty("Nodes")[0].GetProperty("Url").GetString(), Is.EqualTo($"http://127.0.0.1:7781/raven/ravendb/{token}"));
    }

    [Test]
    public async Task A_placeholder_in_the_path_that_was_never_minted_is_refused()
    {
        await OpenLeaseAndMint();
        var response = await Get("/raven/ravendb/tirph_ravendb_aaaaaaaaaaaaaaaaaaaaaaaaaa/databases/Orders/stats", token: null);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(raven.Requests, Is.Empty);
    }

    Task<WebSocket> OpenChanges(string token)
    {
        var sockets = factory.Server.CreateWebSocketClient();
        return sockets.ConnectAsync(new Uri($"ws://localhost/raven/ravendb/{token}/databases/Orders/changes?id=1"), CancellationToken.None);
    }

    [Test]
    public async Task Without_websocket_in_the_grant_the_changes_api_is_refused()
    {
        var token = await OpenLeaseAndMint();
        Assert.That(() => OpenChanges(token), Throws.Exception);
        Assert.That(raven.Requests, Is.Empty);
        Assert.That(Audit(), Does.Contain("WEBSOCKET").And.Contain("not-covered"));
    }

    [Test, Category("changes")]
    public async Task The_changes_api_is_relayed_to_the_node_with_the_certificate_and_audited_open_and_closed()
    {
        var token = await OpenLeaseAndMint();
        using var socket = await OpenChanges(token);

        await socket.SendAsync("watch-docs"u8.ToArray(), WebSocketMessageType.Text, true, CancellationToken.None);
        var buffer = new byte[256];
        var received = await socket.ReceiveAsync(buffer, CancellationToken.None);
        Assert.That(System.Text.Encoding.UTF8.GetString(buffer, 0, received.Count), Is.EqualTo("watch-docs"), "the fake node echoes");
        Assert.That(raven.Requests.Single().Uri, Is.EqualTo("wss://a.raven.example/databases/Orders/changes?id=1"));
        Assert.That(raven.Certificates.Single().Thumbprint, Is.EqualTo(issued.Thumbprint));

        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None);
        Assert.That(socket.CloseStatus, Is.EqualTo(WebSocketCloseStatus.NormalClosure), "the node's close comes back");
        Assert.That(SpinWait.SpinUntil(() => Audit().Contains("closed: 10 bytes up, 10 bytes down"), TimeSpan.FromSeconds(5)), Is.True, Audit());
        Assert.That(Audit(), Does.Contain("\"WEBSOCKET\""));
    }

    [Test, Category("changes")]
    public async Task A_changes_tunnel_closes_when_the_lease_ends()
    {
        var token = await OpenLeaseAndMint();
        using var socket = await OpenChanges(token);

        await client.SendAsync(Signed("/lease/end"));

        // The broker aborts both sides; the client sees its socket end rather than hang.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            await socket.ReceiveAsync(new byte[16], timeout.Token);
        }
        catch (Exception e) when (e is WebSocketException or IOException or OperationCanceledException)
        {
        }
        Assert.That(timeout.IsCancellationRequested, Is.False, "the socket ended before the timeout");
        Assert.That(SpinWait.SpinUntil(() => Audit().Contains("lease-ended"), TimeSpan.FromSeconds(5)), Is.True, Audit());
    }

    sealed record SeenRequest(string Uri, string? Authorization, string? AcceptEncoding);

    sealed class FakeRaven
    {
        public ConcurrentQueue<SeenRequest> Requests { get; } = new();
        public List<X509Certificate2> Certificates { get; } = [];

        public HttpMessageHandler Handler(X509Certificate2 certificate)
        {
            lock (Certificates)
                Certificates.Add(certificate);
            return new Node(this);
        }

        sealed class Node(FakeRaven owner) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                owner.Requests.Enqueue(new(request.RequestUri!.OriginalString, request.Headers.Authorization?.ToString(),
                    request.Headers.AcceptEncoding.Count == 0 ? null : request.Headers.AcceptEncoding.ToString()));
                if (request.Headers.TryGetValues("Sec-WebSocket-Key", out var keys))
                    return await FakeWebSocketNode.UpgradeAsync(keys.Single());
                var body = request.RequestUri!.AbsolutePath switch
                {
                    "/topology" => """{"Nodes":[{"Url":"https://a.raven.example","ClusterTag":"A"}],"Etag":1}""",
                    "/cluster/topology" => """{"Topology":{"AllNodes":{"A":"https://a.raven.example"}},"Leader":"A"}""",
                    _ => """{"ok":true}""",
                };
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
            }
        }
    }
}
