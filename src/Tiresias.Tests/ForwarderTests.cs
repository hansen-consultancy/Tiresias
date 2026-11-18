extern alias forwarder;

using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ForwarderProgram = forwarder::Program;
using IClientProcessLookup = forwarder::Tiresias.Forwarder.IClientProcessLookup;
using LoopbackGuard = forwarder::Tiresias.Forwarder.LoopbackGuard;
using SvcForwarder = forwarder::Tiresias.Forwarder.SvcForwarder;

namespace Tiresias.Tests;

public class LoopbackGuardTests
{
    static IReadOnlyList<string> Check(params (string Key, string Value)[] settings) =>
        LoopbackGuard.NonLoopback(new ConfigurationBuilder()
            .AddInMemoryCollection(settings.Select(s => new KeyValuePair<string, string?>(s.Key, s.Value)))
            .Build());

    [Test]
    public void Loopback_addresses_pass() =>
        Assert.That(Check(("urls", "http://127.0.0.1:7781;http://[::1]:7781;http://localhost:7781")), Is.Empty);

    [TestCase("http://0.0.0.0:7781")]
    [TestCase("http://*:7781")]
    [TestCase("http://+:7781")]
    [TestCase("http://[::]:7781")]
    [TestCase("http://192.168.1.10:7781")]
    [TestCase("http://alice-alice-pc:7781")]
    public void Anything_else_in_urls_is_refused(string url) =>
        Assert.That(Check(("urls", $"http://127.0.0.1:7781;{url}")), Is.EqualTo(new[] { url }));

    [Test]
    public void A_kestrel_endpoint_is_checked_too() =>
        Assert.That(Check(("Kestrel:Endpoints:Http:Url", "http://0.0.0.0:7781")), Is.EqualTo(new[] { "http://0.0.0.0:7781" }));

    [TestCase("http_ports")]
    [TestCase("https_ports")]
    public void A_port_list_binds_every_interface_and_is_refused(string key) =>
        Assert.That(Check((key, "7781")), Is.EqualTo(new[] { $"{key}=7781" }));
}

/// <summary>The forwarder over HTTP, with a fake broker behind its named client.</summary>
public class ForwarderHostTests
{
    const string Observed = @"C:\tools\export.exe (pid 4242)";

    FakeBroker broker = null!;
    WebApplicationFactory<ForwarderProgram> factory = null!;
    HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        broker = new FakeBroker();
        factory = new WebApplicationFactory<ForwarderProgram>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Forwarder:BrokerUrl", "http://broker.test:7780/");
            b.ConfigureTestServices(s =>
            {
                s.RemoveAll<IClientProcessLookup>();
                s.AddSingleton<IClientProcessLookup>(new FixedProcess());
                s.AddHttpClient(SvcForwarder.ClientName).ConfigurePrimaryHttpMessageHandler(() => broker);
            });
        });
        client = factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        client.Dispose();
        factory.Dispose();
        broker.Dispose();
    }

    [Test]
    public async Task A_request_reaches_the_broker_verbatim_with_the_observed_process()
    {
        var message = new HttpRequestMessage(HttpMethod.Post, "/svc/llm/v1/chat?q=a%2Fb");
        message.Headers.Authorization = new("Bearer", "tirph_llm_abc");
        message.Headers.Add("X-Trace", "t-1");
        message.Headers.Add("X-Tiresias-Observed-Process", "forged.exe");
        message.Content = new StringContent("""{"q":1}""", Encoding.UTF8, "application/json");

        var response = await client.SendAsync(message);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo("broker-body"));
        Assert.That(response.Headers.GetValues("X-Broker"), Is.EqualTo(new[] { "yes" }));

        var seen = broker.Requests.Single();
        Assert.That(seen.Method, Is.EqualTo("POST"));
        Assert.That(seen.Uri, Is.EqualTo("http://broker.test:7780/svc/llm/v1/chat?q=a%2Fb"));
        Assert.That(seen.Headers["Authorization"], Is.EqualTo("Bearer tirph_llm_abc"));
        Assert.That(seen.Headers["X-Trace"], Is.EqualTo("t-1"));
        Assert.That(seen.Headers["Content-Type"], Does.StartWith("application/json"));
        Assert.That(seen.Headers["X-Tiresias-Observed-Process"], Is.EqualTo(Observed));
        Assert.That(seen.Headers.ContainsKey("Host"), Is.False);
        Assert.That(seen.Body, Is.EqualTo("""{"q":1}"""));
    }

    [Test]
    public async Task An_encoded_path_is_passed_on_undecoded_for_the_broker_to_refuse()
    {
        await client.GetAsync("/svc/llm/v1/models%2f..%2fadmin");
        Assert.That(broker.Requests.Single().Uri, Is.EqualTo("http://broker.test:7780/svc/llm/v1/models%2f..%2fadmin"));
    }

    [Test]
    public async Task Nothing_outside_svc_is_forwarded()
    {
        var response = await client.PostAsync("/lease/begin", null);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        Assert.That(broker.Requests, Is.Empty);
    }

    sealed class FixedProcess : IClientProcessLookup
    {
        public string? Describe(ConnectionInfo connection) => Observed;
    }

    sealed record SeenRequest(string Method, string Uri, Dictionary<string, string> Headers, string Body);

    [Test]
    public async Task A_websocket_is_relayed_to_the_broker_with_the_observed_process_and_messages_come_back()
    {
        var sockets = factory.Server.CreateWebSocketClient();
        sockets.ConfigureRequest = r => r.Headers["X-Tiresias-Observed-Process"] = "forged.exe";
        using var socket = await sockets.ConnectAsync(new Uri("ws://localhost/raven/orders/tirph_orders_abc/databases/Orders/changes"), CancellationToken.None);

        await socket.SendAsync("ping"u8.ToArray(), System.Net.WebSockets.WebSocketMessageType.Text, true, CancellationToken.None);
        var buffer = new byte[16];
        var received = await socket.ReceiveAsync(buffer, CancellationToken.None);
        Assert.That(System.Text.Encoding.UTF8.GetString(buffer, 0, received.Count), Is.EqualTo("ping"));

        var seen = broker.Requests.Single();
        Assert.That(seen.Uri, Is.EqualTo("ws://broker.test:7780/raven/orders/tirph_orders_abc/databases/Orders/changes"));
        Assert.That(seen.Headers["X-Tiresias-Observed-Process"], Does.Not.Contain("forged.exe"));
        await socket.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
        Assert.That(socket.CloseStatus, Is.EqualTo(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure));
    }

    sealed class FakeBroker : HttpMessageHandler
    {
        public List<SeenRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var headers = request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
                .ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new(request.Method.Method, request.RequestUri!.OriginalString, headers, body));
            if (request.Headers.TryGetValues("Sec-WebSocket-Key", out var keys))
                return await FakeWebSocketNode.UpgradeAsync(keys.Single());

            var response = new HttpResponseMessage(HttpStatusCode.Accepted) { Content = new StringContent("broker-body") };
            response.Headers.Add("X-Broker", "yes");
            return response;
        }
    }
}
