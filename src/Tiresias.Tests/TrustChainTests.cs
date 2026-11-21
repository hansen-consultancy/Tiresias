using System.Net;
using System.Security.Cryptography;
using Tiresias.Client;
using System.Net.Http.Json;
using System.Text.Json;
using Tiresias.Audit;
using Tiresias.Broker;
using Tiresias.Transport;
using Tiresias.Trust;
using Tiresias.Vault;
using Microsoft.AspNetCore.Mvc.Testing;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class TrustChainTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);

    readonly List<Key> keys = [];
    List<TrustLink> chain = null!;
    string genesisHash = "";
    Signer laptop = null!;
    Signer paper = null!;

    [SetUp]
    public void SetUp()
    {
        laptop = NewSigner("alice-laptop");
        paper = NewSigner("alice-paper");
        chain = [TrustChain.Start("personal", "alice", laptop, paper, new(), T0)];
        genesisHash = TrustChain.Hash(chain[0]);
    }

    [TearDown]
    public void TearDown()
    {
        foreach (var key in keys)
            key.Dispose();
        keys.Clear();
    }

    Signer NewSigner(string id)
    {
        var key = Key.Create(SignatureAlgorithm.Ed25519);
        keys.Add(key);
        return new(id, key);
    }

    void Add(LinkBody body, params Signer[] signers) => chain.Add(TrustChain.Append(chain, body, T0, signers));

    TrustVerification Verify(ChainHead? head = null) => TrustChainVerifier.Verify(chain, genesisHash, head);

    TrustState Valid(ChainHead? head = null)
    {
        var result = Verify(head);
        Assert.That(result.Failure, Is.Null);
        return result.State!;
    }

    void AssertFails(TrustFailureKind kind, long seq, ChainHead? head = null)
    {
        var result = Verify(head);
        Assert.That(result.State, Is.Null);
        Assert.That(result.Failure!.Kind, Is.EqualTo(kind), result.Failure.Detail);
        Assert.That(result.Failure.Seq, Is.EqualTo(seq));
    }

    Signer Enrol(string user, bool admin, params Signer[] authorizers)
    {
        var device = NewSigner($"{user}-phone");
        Add(new AddUser(user, admin, device.Describe()), [.. authorizers, device]);
        return device;
    }

    [Test]
    public void Genesis_alone_derives_the_first_admin_with_device_and_paper_key()
    {
        var state = Valid();

        Assert.That(state.Tenant, Is.EqualTo("personal"));
        Assert.That(state.Users["alice"].Admin, Is.True);
        Assert.That(state.DevicesOf("alice").Select(d => (d.Id, d.Paper)),
            Is.EquivalentTo(new[] { ("alice-laptop", false), ("alice-paper", true) }));
        Assert.That(state.Policy.AdminThreshold, Is.EqualTo(1));
        Assert.That(state.Head, Is.EqualTo(new ChainHead(0, genesisHash)));
        Assert.That(state.BreakGlassUses, Is.Empty);
    }

    [Test]
    public void Genesis_without_the_paper_key_signature_is_missing_a_countersignature()
    {
        chain = [TrustChain.Link(0, TrustChain.ZeroHash, T0, new Genesis("personal", "alice", laptop.Describe(), paper.Describe(paper: true), new()), laptop)];
        genesisHash = TrustChain.Hash(chain[0]);
        AssertFails(TrustFailureKind.MissingCountersignature, 0);
    }

    [Test]
    public void A_different_genesis_is_a_mismatch()
    {
        genesisHash = TrustChain.Hash(TrustChain.Start("personal", "mallory", NewSigner("m"), NewSigner("mp"), new(), T0));
        AssertFails(TrustFailureKind.GenesisMismatch, 0);
    }

    [Test]
    public void An_empty_chain_is_a_genesis_mismatch()
    {
        chain = [];
        AssertFails(TrustFailureKind.GenesisMismatch, 0);
    }

    [Test]
    public void A_device_added_by_its_own_users_device_is_accepted()
    {
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);

        Assert.That(Valid().Devices.Keys, Does.Contain("alice-desktop"));
    }

    [Test]
    public void A_device_added_by_another_users_device_is_rejected()
    {
        var anna = Enrol("anna", admin: false, laptop);
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), anna, desktop);

        AssertFails(TrustFailureKind.UnauthorizedSigner, 2);
    }

    [Test]
    public void An_add_device_the_new_device_did_not_countersign_is_rejected()
    {
        Add(new AddDevice("alice", NewSigner("alice-desktop").Describe()), laptop);
        AssertFails(TrustFailureKind.MissingCountersignature, 1);
    }

    [Test]
    public void A_tampered_signature_is_a_bad_signature()
    {
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        var sig = chain[1].Signatures[0].Signature.ToArray();
        sig[0] ^= 1;
        chain[1] = chain[1] with { Signatures = [chain[1].Signatures[0] with { Signature = sig }, chain[1].Signatures[1]] };

        AssertFails(TrustFailureKind.BadSignature, 1);
    }

    [Test]
    public void A_link_not_pointing_at_the_previous_hash_is_a_bad_prev()
    {
        var desktop = NewSigner("alice-desktop");
        chain.Add(TrustChain.Link(1, TrustChain.ZeroHash, T0, new AddDevice("alice", desktop.Describe()), laptop, desktop));
        AssertFails(TrustFailureKind.BadPrev, 1);
    }

    [Test]
    public void A_skipped_seq_is_a_bad_seq()
    {
        var desktop = NewSigner("alice-desktop");
        chain.Add(TrustChain.Link(2, TrustChain.Hash(chain[0]), T0, new AddDevice("alice", desktop.Describe()), laptop, desktop));
        AssertFails(TrustFailureKind.BadSeq, 1);
    }

    [Test]
    public void A_signer_unknown_to_the_chain_is_unauthorized()
    {
        Add(new SetPolicy(new()), NewSigner("stranger"));
        AssertFails(TrustFailureKind.UnauthorizedSigner, 1);
    }

    [Test]
    public void A_non_admin_cannot_sign_an_admin_link()
    {
        var anna = Enrol("anna", admin: false, laptop);
        Enrol("bob", admin: false, anna);
        AssertFails(TrustFailureKind.UnauthorizedSigner, 2);
    }

    [Test]
    public void A_revoked_device_cannot_sign_later_links()
    {
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        Add(new RevokeDevice("alice-laptop"), desktop);
        Assert.That(Valid().Devices.Keys, Does.Not.Contain("alice-laptop"));

        Add(new SetPolicy(new()), laptop);
        AssertFails(TrustFailureKind.RevokedSigner, 3);
    }

    [Test]
    public void An_admin_may_revoke_another_users_device_but_a_peer_may_not()
    {
        Enrol("anna", admin: false, laptop);
        var bob = Enrol("bob", admin: false, laptop);
        Add(new RevokeDevice("anna-phone"), bob);
        AssertFails(TrustFailureKind.UnauthorizedSigner, 3);

        chain.RemoveAt(3);
        Add(new RevokeDevice("anna-phone"), laptop);
        Assert.That(Valid().DevicesOf("anna"), Is.Empty);
    }

    [Test]
    public void Removing_a_user_retires_their_devices()
    {
        var anna = Enrol("anna", admin: false, laptop);
        Add(new RemoveUser("anna"), laptop);
        Add(new RevokeDevice("alice-paper"), anna);

        AssertFails(TrustFailureKind.RevokedSigner, 3);
    }

    [Test]
    public void The_paper_key_recovers_after_every_device_is_revoked_and_is_reported()
    {
        Add(new RevokeDevice("alice-laptop"), laptop);
        var replacement = NewSigner("alice-new-laptop");
        Add(new AddDevice("alice", replacement.Describe()), paper, replacement);

        var state = Valid();
        Assert.That(state.DevicesOf("alice").Select(d => d.Id), Is.EquivalentTo(new[] { "alice-paper", "alice-new-laptop" }));
        Assert.That(state.BreakGlassUses, Is.EqualTo(new[] { new BreakGlassUse(2, "alice-paper", "alice") }));
    }

    [Test]
    public void M_of_n_counts_distinct_admin_users_not_devices()
    {
        var anna = Enrol("anna", admin: true, laptop);
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        Add(new SetPolicy(new(AdminThreshold: 2)), laptop);

        var bob = NewSigner("bob-phone");
        Add(new AddUser("bob", false, bob.Describe()), laptop, desktop, bob);
        AssertFails(TrustFailureKind.InsufficientAdminSignatures, 4);

        chain[4] = TrustChain.Cosign(chain[4], anna);
        Assert.That(Valid().Users.Keys, Does.Contain("bob"));
    }

    [Test]
    public void A_threshold_above_the_admin_count_is_invalid()
    {
        Add(new SetPolicy(new(AdminThreshold: 2)), laptop);
        AssertFails(TrustFailureKind.InvalidLink, 1);
    }

    [Test]
    public void An_extension_of_the_accepted_head_verifies()
    {
        var head = Valid().Head;
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);

        Assert.That(Valid(head).Head.Seq, Is.EqualTo(1));
    }

    [Test]
    public void A_chain_shorter_than_the_accepted_head_is_a_rollback()
    {
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        Add(new RevokeDevice("alice-desktop"), laptop);
        var head = Valid().Head;

        chain.RemoveAt(2);
        AssertFails(TrustFailureKind.Rollback, 1, head);
    }

    [Test]
    public void A_chain_differing_at_an_accepted_seq_is_a_fork()
    {
        var desktop = NewSigner("alice-desktop");
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        Add(new RevokeDevice("alice-desktop"), laptop);
        var head = Valid().Head;

        chain.RemoveAt(2);
        Add(new SetPolicy(new()), laptop);
        AssertFails(TrustFailureKind.Fork, 2, head);
    }

    [Test]
    public void The_canonical_json_round_trips_to_the_same_hashes()
    {
        Enrol("anna", admin: true, laptop);
        Add(new AddBroker("vps-broker", NewSigner("broker").Describe().PublicKey), laptop);

        var parsed = TrustLinkJson.ParseChain(TrustLinkJson.WriteChain(chain))!;

        Assert.That(parsed.Select(TrustChain.Hash), Is.EqualTo(chain.Select(TrustChain.Hash)));
        Assert.That(TrustChainVerifier.Verify(parsed, genesisHash).State!.Brokers.Keys, Is.EqualTo(new[] { "vps-broker" }));
    }

    [Test]
    public void Malformed_json_is_not_a_chain() =>
        Assert.That(TrustLinkJson.ParseChain("[{\"seq\":0}]"u8), Is.Null);
}

/// <summary>The broker with a trust chain configured: the chain, not the static device list, decides who may sign.</summary>
public class BrokerTrustChainTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);

    string dir = "";
    string chainPath = "";
    TestVault vault = null!;
    Signer laptop = null!;
    Signer paper = null!;
    Key configured = null!;
    List<TrustLink> chain = null!;
    WebApplicationFactory<Program> factory = null!;
    HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        dir = Directory.CreateTempSubdirectory("tir-trust-").FullName;
        chainPath = Path.Combine(dir, "chain.json");
        vault = TestVault.Create();
        VaultFile.Save(Path.Combine(dir, "vault.json"), vault.Document);
        laptop = new("alice-laptop", Key.Create(SignatureAlgorithm.Ed25519));
        paper = new("alice-paper", Key.Create(SignatureAlgorithm.Ed25519));
        configured = Key.Create(SignatureAlgorithm.Ed25519);
        chain = [TrustChain.Start("personal", "alice", laptop, paper, new(), T0)];
        File.WriteAllBytes(chainPath, TrustLinkJson.WriteChain(chain));
        (factory, client) = Start();
    }

    [TearDown]
    public void TearDown()
    {
        client.Dispose();
        factory.Dispose();
        laptop.Key.Dispose();
        paper.Key.Dispose();
        configured.Dispose();
        vault.Dispose();
        TestDirectory.Delete(dir);
    }

    (WebApplicationFactory<Program>, HttpClient) Start()
    {
        var f = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Broker:VaultPath", Path.Combine(dir, "vault.json"));
            b.UseSetting("Broker:AuditPath", Path.Combine(dir, "audit.jsonl"));
            b.UseSetting("Broker:IdentityKeyPath", Path.Combine(dir, "identity.key"));
            b.UseSetting("Broker:Devices:configured", Convert.ToBase64String(configured.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
            b.UseSetting("Broker:TrustChainPath", chainPath);
            b.UseSetting("Broker:PinnedGenesisHash", TrustChain.Hash(chain[0]));
        });
        return (f, f.CreateClient());
    }

    static HttpRequestMessage Signed(string deviceId, Key key, string endpoint, byte[]? body = null)
    {
        body ??= [];
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var message = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new ByteArrayContent(body) };
        message.Content.Headers.ContentType = new("application/json");
        message.Headers.Add(RequestSignature.DeviceHeader, deviceId);
        message.Headers.Add(RequestSignature.TimestampHeader, ts.ToString(System.Globalization.CultureInfo.InvariantCulture));
        message.Headers.Add(RequestSignature.SignatureHeader, Convert.ToBase64String(RequestSignature.Sign(key, "POST", endpoint, ts, body)));
        return message;
    }

    Task<HttpResponseMessage> PostChain(IEnumerable<TrustLink> links) =>
        client.SendAsync(Signed(laptop.DeviceId, laptop.Key, "/trust/chain", TrustLinkJson.WriteChain(links)));

    [Test]
    public async Task Only_the_chains_active_non_paper_devices_may_sign()
    {
        Assert.That((await client.SendAsync(Signed(laptop.DeviceId, laptop.Key, "/lease/end"))).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
        Assert.That((await client.SendAsync(Signed(paper.DeviceId, paper.Key, "/lease/end"))).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That((await client.SendAsync(Signed("configured", configured, "/lease/end"))).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task A_longer_chain_enrols_its_new_device_and_is_audited()
    {
        using var desktopKey = Key.Create(SignatureAlgorithm.Ed25519);
        var desktop = new Signer("alice-desktop", desktopKey);
        chain.Add(TrustChain.Append(chain, new AddDevice("alice", desktop.Describe()), T0, laptop, desktop));

        var response = await PostChain(chain);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("added").GetInt32(), Is.EqualTo(1));

        Assert.That((await client.SendAsync(Signed(desktop.DeviceId, desktopKey, "/lease/end"))).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
        Assert.That(File.ReadAllText(Path.Combine(dir, "audit.jsonl")), Does.Contain("\"kind\":\"TrustLink\"").And.Contain("seq 1 add-device"));
        Assert.That(AuditLog.Verify(Path.Combine(dir, "audit.jsonl")), Is.Null);
    }

    [Test]
    public async Task The_accepted_chain_is_served_to_signed_devices_for_them_to_verify()
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        using var get = new HttpRequestMessage(HttpMethod.Get, "/trust/chain");
        get.Headers.Add(RequestSignature.DeviceHeader, laptop.DeviceId);
        get.Headers.Add(RequestSignature.TimestampHeader, ts.ToString(System.Globalization.CultureInfo.InvariantCulture));
        get.Headers.Add(RequestSignature.SignatureHeader, Convert.ToBase64String(RequestSignature.Sign(laptop.Key, "GET", "/trust/chain", ts, [])));

        var response = await client.SendAsync(get);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var served = TrustLinkJson.ParseChain(await response.Content.ReadAsByteArrayAsync());
        Assert.That(BrokerTrust.Evaluate(served, TrustChain.Hash(chain[0]), null, [], laptop.DeviceId).Head, Is.EqualTo(new ChainHead(0, TrustChain.Hash(chain[0]))));

        Assert.That((await client.GetAsync("/trust/chain")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized), "unsigned");
    }

    [Test]
    public async Task A_shorter_chain_is_refused_as_a_rollback_and_audited()
    {
        using var desktopKey = Key.Create(SignatureAlgorithm.Ed25519);
        var desktop = new Signer("alice-desktop", desktopKey);
        chain.Add(TrustChain.Append(chain, new AddDevice("alice", desktop.Describe()), T0, laptop, desktop));
        Assert.That((await PostChain(chain)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var response = await PostChain(chain.Take(1));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reason").GetString(), Is.EqualTo("Rollback"));
        Assert.That(File.ReadAllText(Path.Combine(dir, "audit.jsonl")), Does.Contain("\"kind\":\"TrustRejected\""));
    }

    [Test]
    public async Task Revoking_the_device_that_opened_the_lease_ends_it_and_its_placeholders()
    {
        var begin = await client.SendAsync(Signed(laptop.DeviceId, laptop.Key, "/lease/begin"));
        Assert.That(begin.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var offerJson = await begin.Content.ReadFromJsonAsync<JsonElement>();
        var offer = new LeaseOffer(offerJson.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(offerJson.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(offerJson.GetProperty("hardCapAt").GetInt64()));
        await client.SendAsync(Signed(laptop.DeviceId, laptop.Key, "/lease/seal", JsonSerializer.SerializeToUtf8Bytes(vault.SealBody(offer), JsonSerializerOptions.Web)));
        var mint = await client.SendAsync(Signed(laptop.DeviceId, laptop.Key, "/placeholder", JsonSerializer.SerializeToUtf8Bytes(
            vault.MintApproval(new("claude:test", null, "llm", null, "testing", TimeSpan.FromHours(1))), JsonSerializerOptions.Web)));
        var token = (await mint.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;

        using var desktopKey = Key.Create(SignatureAlgorithm.Ed25519);
        var desktop = new Signer("alice-desktop", desktopKey);
        chain.Add(TrustChain.Append(chain, new AddDevice("alice", desktop.Describe()), T0, laptop, desktop));
        chain.Add(TrustChain.Append(chain, new RevokeDevice(laptop.DeviceId), T0, desktop));
        Assert.That((await PostChain(chain)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var svc = new HttpRequestMessage(HttpMethod.Get, "/svc/llm/v1/models");
        svc.Headers.Authorization = new("Bearer", token);
        var response = await client.SendAsync(svc);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
        Assert.That((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reason").GetString(), Is.EqualTo("no-lease"));
        Assert.That(File.ReadLines(Path.Combine(dir, "audit.jsonl")), Has.Exactly(1).Contains("\"kind\":\"LeaseEnd\"").And.Contains("device-revoked"));
    }

    [Test]
    public async Task A_rolled_back_chain_file_stops_the_broker_on_restart()
    {
        using var desktopKey = Key.Create(SignatureAlgorithm.Ed25519);
        var desktop = new Signer("alice-desktop", desktopKey);
        chain.Add(TrustChain.Append(chain, new AddDevice("alice", desktop.Describe()), T0, laptop, desktop));
        Assert.That((await PostChain(chain)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        File.WriteAllBytes(chainPath, TrustLinkJson.WriteChain(chain.Take(1)));

        Assert.That(() => new TrustChainFile(chainPath, TrustChain.Hash(chain[0]), new AuditLog(Path.Combine(dir, "audit.jsonl"), TimeProvider.System)),
            Throws.InstanceOf<InvalidDataException>().With.Message.Contains("Rollback"));
    }
}

public class BrokerTrustTests
{
    static readonly DateTimeOffset T0 = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);

    Signer laptop = null!;
    Signer paper = null!;
    Signer desktop = null!;
    byte[] brokerKey = null!;
    List<TrustLink> chain = null!;
    string genesis = "";

    [SetUp]
    public void SetUp()
    {
        laptop = new("alice-laptop", Key.Create(SignatureAlgorithm.Ed25519));
        paper = new("alice-paper", Key.Create(SignatureAlgorithm.Ed25519));
        desktop = new("alice-desktop", Key.Create(SignatureAlgorithm.Ed25519));
        brokerKey = RandomNumberGenerator.GetBytes(32);
        chain = [TrustChain.Start("personal", "alice", laptop, paper, new(), T0)];
        genesis = TrustChain.Hash(chain[0]);
    }

    [TearDown]
    public void TearDown()
    {
        laptop.Key.Dispose();
        paper.Key.Dispose();
        desktop.Key.Dispose();
    }

    void Add(LinkBody body, params Signer[] signers) => chain.Add(TrustChain.Append(chain, body, T0, signers));

    [Test]
    public void A_chain_from_the_pinned_genesis_that_trusts_this_device_yields_its_head()
    {
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        var result = BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-desktop");
        Assert.That(result.Error, Is.Null);
        Assert.That(result.Head!.Seq, Is.EqualTo(1));
    }

    [Test]
    public void Another_genesis_is_refused() =>
        Assert.That(BrokerTrust.Evaluate(chain, new string('0', 64), null, brokerKey, "alice-laptop").Error, Does.Contain("genesis"));

    [Test]
    public void An_older_chain_than_the_accepted_head_is_a_rollback()
    {
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        var head = BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-laptop").Head;
        Assert.That(BrokerTrust.Evaluate(chain.Take(1).ToArray(), genesis, head, brokerKey, "alice-laptop").Error, Does.Contain("rollback"));
    }

    [Test]
    public void A_chain_that_revoked_this_device_is_refused()
    {
        Add(new AddDevice("alice", desktop.Describe()), laptop, desktop);
        Add(new RevokeDevice("alice-desktop"), laptop);
        Assert.That(BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-desktop").Error, Does.Contain("no longer trusts"));
    }

    [Test]
    public void A_paper_key_is_not_a_device_that_unlocks() =>
        Assert.That(BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-paper").Error, Does.Contain("no longer trusts"));

    [Test]
    public void Once_the_chain_names_brokers_the_pinned_identity_must_be_one()
    {
        Assert.That(BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-laptop").Trusted, Is.True, "no brokers listed yet");
        Add(new AddBroker("vps-broker", RandomNumberGenerator.GetBytes(32)), laptop);
        Assert.That(BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-laptop").Error, Does.Contain("broker identity"));
        Add(new AddBroker("vps-broker-2", brokerKey), laptop);
        Assert.That(BrokerTrust.Evaluate(chain, genesis, null, brokerKey, "alice-laptop").Trusted, Is.True);
    }

    [Test]
    public void Unparseable_json_is_refused() =>
        Assert.That(BrokerTrust.Evaluate(TrustLinkJson.ParseChain("nope"u8), genesis, null, brokerKey, "alice-laptop").Error, Does.Contain("JSON"));
}
