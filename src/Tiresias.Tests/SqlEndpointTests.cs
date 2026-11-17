using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Tiresias.Access;
using Tiresias.Audit;
using Tiresias.Broker;
using Tiresias.Leases;
using Tiresias.Transport;
using Tiresias.Vault;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class SqlAuthorizationTests
{
    const string ReadSecret = "Server=db.example;Database=AppDb;User ID=tiresias_provisioner;Password=p-read";

    TestVault vault = null!;
    Key identity = null!;
    ManualTime time = null!;
    string auditPath = "";
    BrokerState state = null!;

    [SetUp]
    public void SetUp()
    {
        vault = TestVault.CreateWithSql();
        identity = Key.Create(SignatureAlgorithm.Ed25519);
        time = new ManualTime(new(2026, 11, 17, 8, 0, 0, TimeSpan.Zero));
        auditPath = Path.Combine(Path.GetTempPath(), $"tir-sql-{Guid.NewGuid():N}.jsonl");
        state = new BrokerState(vault.Document, LeaseTerms.Workday(TimeZoneInfo.FindSystemTimeZoneById("Europe/Brussels")),
            new AuditLog(auditPath, time), identity, time);
        var (offer, _) = state.BeginLease("laptop");
        state.Seal(offer.LeaseId, vault.SealTo(offer));
    }

    [TearDown]
    public void TearDown()
    {
        state.Dispose();
        identity.Dispose();
        vault.Dispose();
        File.Delete(auditPath);
    }

    string Mint(string service = "appdb", string? ceiling = null) =>
        state.Mint(new AccessRequest("claude:test", null, service, ceiling, "testing", TimeSpan.FromHours(1))).Minted!.Token;

    string Audit() => File.ReadAllText(auditPath);

    [Test]
    public void A_select_on_the_read_grant_gets_the_provisioner_secret_and_is_audited_without_its_text()
    {
        var (allowed, refusal) = state.AuthorizeSql("Bearer " + Mint(), "appdb", "read", "SELECT Secretish FROM dbo.Orders");
        Assert.That(refusal, Is.Null);
        using (allowed)
        {
            Assert.That(allowed!.Grant.Name, Is.EqualTo("read"));
            Assert.That(allowed.TakeSecret(), Is.EqualTo(ReadSecret));
            allowed.Complete(200);
        }

        Assert.That(Audit(), Does.Contain("\"kind\":\"Allow\"").And.Contain("\"method\":\"SQL\"").And.Contain("\"reason\":\"select\""));
        Assert.That(Audit(), Does.Not.Contain("Secretish"));
    }

    [Test]
    public void A_write_on_the_read_grant_is_refused_with_the_classifier_reason()
    {
        var (allowed, refusal) = state.AuthorizeSql("Bearer " + Mint(), "appdb", "read", "DELETE FROM dbo.Orders WHERE Marker = 1");
        Assert.That(allowed, Is.Null);
        Assert.That(refusal!.Status, Is.EqualTo(403));
        Assert.That(refusal.Reason, Is.EqualTo("not-read-only"));
        Assert.That(refusal.Problems, Is.EqualTo(new[] { "does not start with SELECT or WITH" }));
        Assert.That(Audit(), Does.Contain("not-read-only").And.Not.Contain("Marker"));
    }

    [Test]
    public void The_write_grant_runs_any_statement_within_the_ceiling()
    {
        var (allowed, refusal) = state.AuthorizeSql("Bearer " + Mint(), "appdb", "write", "DELETE FROM dbo.Orders");
        Assert.That(refusal, Is.Null);
        allowed!.Dispose();
    }

    [Test]
    public void A_grant_above_the_placeholders_ceiling_is_not_covered()
    {
        var (_, refusal) = state.AuthorizeSql("Bearer " + Mint(ceiling: "read"), "appdb", "write", "SELECT 1");
        Assert.That(refusal, Is.EqualTo(new Refusal(403, "not-covered")));
    }

    [TestCase("admin")]
    [TestCase("READ")]
    public void Only_the_read_and_write_grants_exist_for_sql(string grant)
    {
        var (_, refusal) = state.AuthorizeSql("Bearer " + Mint(), "appdb", grant, "SELECT 1");
        Assert.That(refusal, Is.EqualTo(new Refusal(403, "not-covered")));
    }

    [Test]
    public void A_placeholder_for_another_service_is_refused()
    {
        var (_, refusal) = state.AuthorizeSql("Bearer " + Mint("llm"), "appdb", "read", "SELECT 1");
        Assert.That(refusal, Is.EqualTo(new Refusal(403, "wrong-service")));
    }

    [Test]
    public void An_http_service_is_never_handed_to_the_sql_gateway_even_with_grants_named_read()
    {
        // Its secret is a bearer token; parsed as a connection string it must never be.
        var (allowed, refusal) = state.AuthorizeSql("Bearer " + Mint("llm"), "llm", "read", "SELECT 1");
        Assert.That(allowed, Is.Null);
        Assert.That(refusal, Is.EqualTo(new Refusal(404, "not-sql")));
    }

    [Test]
    public void Ending_a_lease_raises_LeaseEnded_with_its_id()
    {
        var ended = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        state.LeaseEnded += id => ended.TrySetResult(id);
        var token = Mint();
        var (allowed, _) = state.AuthorizeSql("Bearer " + token, "appdb", "read", "SELECT 1");
        var leaseId = allowed!.LeaseId;
        allowed.Dispose();

        state.End();

        Assert.That(ended.Task.Wait(TimeSpan.FromSeconds(5)), Is.True);
        Assert.That(ended.Task.Result, Is.EqualTo(leaseId));
    }
}

/// <summary><c>POST /sql</c> over HTTP, with a fake gateway in place of SQL Server.</summary>
public class SqlEndpointTests
{
    string dir = "";
    TestVault vault = null!;
    Key device = null!;
    FakeGateway gateway = null!;
    WebApplicationFactory<Program> factory = null!;
    HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        dir = Directory.CreateTempSubdirectory("tir-sql-host-").FullName;
        vault = TestVault.CreateWithSql();
        VaultFile.Save(Path.Combine(dir, "vault.json"), vault.Document);
        device = Key.Create(SignatureAlgorithm.Ed25519);
        gateway = new FakeGateway();

        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Broker:VaultPath", Path.Combine(dir, "vault.json"));
            b.UseSetting("Broker:AuditPath", Path.Combine(dir, "audit.jsonl"));
            b.UseSetting("Broker:IdentityKeyPath", Path.Combine(dir, "identity.key"));
            b.UseSetting("Broker:SqlMaxRows", "2");
            b.UseSetting("Broker:Devices:laptop", Convert.ToBase64String(device.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
            b.ConfigureTestServices(s => s.AddSingleton<ISqlGateway>(gateway));
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

    async Task<(string LeaseId, string Token)> OpenLeaseAndMint()
    {
        var offerJson = await (await client.SendAsync(Signed("/lease/begin"))).Content.ReadFromJsonAsync<JsonElement>();
        var offer = new LeaseOffer(offerJson.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(offerJson.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(offerJson.GetProperty("hardCapAt").GetInt64()));
        await client.SendAsync(Signed("/lease/seal", new { offer.LeaseId, deks = vault.SealTo(offer) }));
        var mint = await client.SendAsync(Signed("/placeholder",
            new { consumer = "claude:test", serviceSlug = "appdb", purpose = "testing", duration = "01:00:00" }));
        return (offer.LeaseId, (await mint.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!);
    }

    Task<HttpResponseMessage> Sql(string grant, string token, object body)
    {
        var message = new HttpRequestMessage(HttpMethod.Post, $"/sql/appdb/{grant}") { Content = JsonContent.Create(body) };
        message.Headers.Authorization = new("Bearer", token);
        return client.SendAsync(message);
    }

    [Test]
    public async Task A_read_runs_through_the_gateway_read_only_capped_and_needs_no_device_signature()
    {
        var (leaseId, token) = await OpenLeaseAndMint();
        var response = await Sql("read", token, new { sql = "SELECT Id FROM dbo.Orders WHERE Total > @min", parameters = new { min = 10, name = "x", flag = true, none = (string?)null } });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(json.GetProperty("rows").GetArrayLength(), Is.EqualTo(1));
        Assert.That(json.GetProperty("rows")[0].GetProperty("Id").GetInt32(), Is.EqualTo(7));
        Assert.That(json.GetProperty("truncated").GetBoolean(), Is.False);

        var (target, query) = gateway.Calls.Single();
        Assert.That(target.LeaseId, Is.EqualTo(leaseId));
        Assert.That(target.Grant, Is.EqualTo("read"));
        Assert.That(target.ProvisionerConnectionString, Does.Contain("tiresias_provisioner"));
        Assert.That(query.ReadOnly, Is.True);
        Assert.That(query.MaxRows, Is.EqualTo(2));
        Assert.That(query.Parameters["min"], Is.EqualTo(10L));
        Assert.That(query.Parameters["name"], Is.EqualTo("x"));
        Assert.That(query.Parameters["flag"], Is.EqualTo(true));
        Assert.That(query.Parameters["none"], Is.Null);
    }

    [Test]
    public async Task A_write_on_the_read_grant_never_reaches_the_gateway()
    {
        var (_, token) = await OpenLeaseAndMint();
        var response = await Sql("read", token, new { sql = "SELECT 1; DROP TABLE dbo.Orders" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reason").GetString(), Is.EqualTo("not-read-only"));
        Assert.That(gateway.Calls, Is.Empty);
    }

    [Test]
    public async Task The_write_grant_is_not_read_only()
    {
        var (_, token) = await OpenLeaseAndMint();
        await Sql("write", token, new { sql = "UPDATE dbo.Orders SET Total = 0" });
        Assert.That(gateway.Calls.Single().Query.ReadOnly, Is.False);
    }

    [Test]
    public async Task A_sql_error_comes_back_as_422_with_its_number()
    {
        var (_, token) = await OpenLeaseAndMint();
        gateway.Error = new SqlStatementException(208, "Invalid object name 'dbo.Nope'.");
        var response = await Sql("read", token, new { sql = "SELECT * FROM dbo.Nope" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.UnprocessableEntity));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("number").GetInt32(), Is.EqualTo(208));
    }

    [TestCase("bad-name", "1")]
    [TestCase("ok", "{\"nested\":1}")]
    public async Task A_parameter_that_is_not_a_named_scalar_is_refused(string name, string valueJson)
    {
        var (_, token) = await OpenLeaseAndMint();
        var body = JsonDocument.Parse($"{{\"sql\":\"SELECT @ok\",\"parameters\":{{\"{name}\":{valueJson}}}}}").RootElement;
        var response = await Sql("read", token, body);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(gateway.Calls, Is.Empty);
    }

    [Test]
    public async Task Ending_the_lease_drops_its_temporary_logins()
    {
        var (leaseId, _) = await OpenLeaseAndMint();
        await client.SendAsync(Signed("/lease/end"));
        Assert.That(gateway.Ended.Task.Wait(TimeSpan.FromSeconds(5)), Is.True);
        Assert.That(gateway.Ended.Task.Result, Is.EqualTo(leaseId));
    }

    sealed class FakeGateway : ISqlGateway
    {
        public ConcurrentQueue<(SqlLeaseTarget Target, SqlQuery Query)> Calls { get; } = new();
        public TaskCompletionSource<string> Ended { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public SqlStatementException? Error { get; set; }

        public Task<SqlResult> QueryAsync(SqlLeaseTarget target, SqlQuery query, CancellationToken ct)
        {
            Calls.Enqueue((target, query));
            if (Error is not null)
                throw Error;
            return Task.FromResult(new SqlResult([new Dictionary<string, object?> { ["Id"] = 7 }], false, -1));
        }

        public Task EndLeaseAsync(string leaseId)
        {
            Ended.TrySetResult(leaseId);
            return Task.CompletedTask;
        }
    }
}
