using System.Text.Json.Nodes;
using NSec.Cryptography;
using Tiresias.EnvironmentVariables;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class EnvironmentFileTests
{
    const string IntegrityReason = "The sealed environment could not be authenticated.";
    static readonly SealedEnvironment Policy = SealedEnvironment.Empty.WithGlobal([new("TOKEN", "test-value")])
        .WithPlaceholder(new("TOKEN", "example", "API_URL"))
        .WithNuGetSource(new("https://feed.example/v3/index.json", "TOKEN", "tester"));

    string path = null!;
    EnvironmentFile file = null!;
    Key key = null!;
    IKeyWrapper hello = null!;

    [SetUp]
    public void SetUp()
    {
        path = Path.Combine(Path.GetTempPath(), $"environment-{Guid.NewGuid():N}.json");
        file = new(path);
        key = Key.Create(KeyAgreementAlgorithm.X25519);
        hello = X25519KeyWrapper.ForKey("hello", key);
    }

    [TearDown]
    public void TearDown()
    {
        key.Dispose();
        File.Delete(path);
    }

    string Seal(string id = EnvironmentFile.Id) => UserSecretsVault.Seal(id, 3, Policy.ToDocument(), [hello]);

    [Test]
    public void A_new_store_is_empty_and_existing_sealed_policy_opens_without_conversion()
    {
        Assert.That(file.Exists, Is.False);
        Assert.That(file.Open(hello), Is.EqualTo((SealedEnvironment.Empty, 0)));
        File.WriteAllText(path, Seal());
        var (environment, version) = file.Open(hello);
        Assert.That(version, Is.EqualTo(3));
        Assert.That(JsonNode.DeepEquals(environment.ToDocument(), Policy.ToDocument()), Is.True);
        Assert.That(file.Opens(hello), Is.True);
        var snapshot = file.ReadForDelivery(hello);
        Assert.DoesNotThrow(snapshot.EnsureCurrent);
    }

    [TestCase("")]
    [TestCase("{")]
    [TestCase("""{ "variables": {"TOKEN": "test-value"} }""")]
    [TestCase("""{ "$tiresias": {"v":"test-value","sealed":"AA=="} }""")]
    [TestCase("""{ "$tiresias": {"v":1,"sealed":"e30="} }""")]
    public void A_present_but_unreadable_policy_yields_only_the_integrity_reason(string contents)
    {
        File.WriteAllText(path, contents);
        Assert.That(file.Exists, Is.True);
        Assert.That(Assert.Throws<EnvironmentIntegrityException>(() => file.ReadForDelivery(hello))!.Message, Is.EqualTo(IntegrityReason));
        Assert.That(file.Opens(hello), Is.False);
    }

    [TestCase("root")]
    [TestCase("envelope")]
    public void Plaintext_additions_are_refused_before_delivery_or_recovery(string location)
    {
        var body = JsonNode.Parse(Seal())!.AsObject();
        var edited = location == "root" ? body : body[SecretsFile.EnvelopeProperty]!.AsObject();
        edited["extra"] = "test-value";
        File.WriteAllText(path, body.ToJsonString());
        Assert.That(Assert.Throws<EnvironmentIntegrityException>(() => file.ReadForDelivery(hello))!.Message, Is.EqualTo(IntegrityReason));
        Assert.That(Assert.Throws<EnvironmentIntegrityException>(() => file.Rewrap(hello, hello))!.Message, Is.EqualTo(IntegrityReason));
    }

    [Test]
    public void A_document_sealed_for_a_project_is_refused_by_the_environment_reader()
    {
        File.WriteAllText(path, Seal("test-project"));
        Assert.That(Assert.Throws<EnvironmentIntegrityException>(() => file.ReadForDelivery(hello))!.Message, Is.EqualTo(IntegrityReason));
    }

    [Test]
    public void Recovery_retains_the_authenticated_policy_and_version()
    {
        using var replacementKey = Key.Create(KeyAgreementAlgorithm.X25519);
        using var recoveryKey = Key.Create(KeyAgreementAlgorithm.X25519);
        var replacement = X25519KeyWrapper.ForKey("hello", replacementKey);
        var recovery = X25519KeyWrapper.ForKey("recovery", recoveryKey);
        File.WriteAllText(path, UserSecretsVault.Seal(EnvironmentFile.Id, 3, Policy.ToDocument(), [hello, recovery]));

        Assert.That(file.Opens(replacement), Is.False);
        var (outcome, text, recoveryOpens) = file.Rewrap(replacement, recovery);
        Assert.That(outcome, Is.EqualTo(RewrapOutcome.Rewrapped));
        Assert.That(recoveryOpens, Is.True);
        File.WriteAllText(path, text);
        var (restored, version) = file.Open(replacement);
        Assert.That(version, Is.EqualTo(3));
        Assert.That(JsonNode.DeepEquals(restored.ToDocument(), Policy.ToDocument()), Is.True);
    }

    [TestCase("nonce")]
    [TestCase("ciphertext")]
    public void Incomplete_or_inauthentic_ciphertext_yields_no_environment(string field)
    {
        var blob = JsonNode.Parse(SecretsFile.ReadSealedOnly(Seal()))!.AsObject();
        var bytes = Convert.FromBase64String((string)blob[field]!);
        bytes[^1] ^= 1;
        blob[field] = Convert.ToBase64String(field == "nonce" ? bytes[..1] : bytes);
        File.WriteAllText(path, SecretsFile.Write(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(blob)));
        Assert.That(Assert.Throws<EnvironmentIntegrityException>(() => file.ReadForDelivery(hello))!.Message, Is.EqualTo(IntegrityReason));
        Assert.That(file.Opens(hello), Is.False);
    }

    [TestCase(true)]
    [TestCase(false)]
    public void A_pending_read_refuses_a_replaced_or_removed_store(bool replace)
    {
        File.WriteAllText(path, Seal());
        var snapshot = file.ReadForDelivery(hello);
        if (replace)
            File.WriteAllText(path, UserSecretsVault.Seal(EnvironmentFile.Id, 4, SealedEnvironment.Empty.ToDocument(), [hello]));
        else
            File.Delete(path);
        Assert.That(Assert.Throws<EnvironmentIntegrityException>(snapshot.EnsureCurrent)!.Message,
            Is.EqualTo("The sealed environment changed during this request. Request access again."));
    }

    [Test]
    public async Task Command_consent_and_delivery_use_the_same_folder_and_mode()
    {
        var policy = Policy.WithFolder(@"C:\work", [new("NAME", "folder-test-value")]);
        File.WriteAllText(path, UserSecretsVault.Seal(EnvironmentFile.Id, 4, policy.ToDocument(), [hello]));
        var snapshot = file.ReadForDelivery(hello);
        var endpoint = new Uri("http://localhost:7777");
        var (variables, missing, terms) = snapshot.SelectForCommand(@"C:\work\project", ["TOKEN", "NAME"], endpoint);

        Assert.That(missing, Is.Empty);
        Assert.That(terms, Does.Contain(@"NAME (folder C:\work, raw value)"));
        Assert.That(terms.Single(t => t.StartsWith("TOKEN", StringComparison.Ordinal)), Does.Contain("global, placeholder for example, API_URL = "));
        Assert.That(string.Join(" ", terms), Does.Not.Contain("test-value"));

        var delivered = await snapshot.DeliverAsync(variables, endpoint,
            (_, _) => Task.FromResult(new MintedPlaceholder("test-placeholder")), _ => throw new AssertionException("Unexpected revocation"), default);
        Assert.That(delivered.Variables["NAME"], Is.EqualTo("folder-test-value"));
        Assert.That(delivered.Variables["TOKEN"], Is.EqualTo("test-placeholder"));
        Assert.That(delivered.Variables["API_URL"], Does.StartWith(endpoint.AbsoluteUri));
    }

    [TestCase(false)]
    [TestCase(true)]
    public void Command_delivery_revokes_prepared_placeholders_when_the_approval_changes(bool lockSession)
    {
        var policy = Policy.WithGlobal([new("NAME", "tirph_synthetic-raw-value")]);
        File.WriteAllText(path, UserSecretsVault.Seal(EnvironmentFile.Id, 4, policy.ToDocument(), [hello]));
        var snapshot = file.ReadForDelivery(hello);
        var revoked = new List<string>();
        var unlocked = true;
        var error = Assert.ThrowsAsync<EnvironmentIntegrityException>(() => snapshot.DeliverAsync(snapshot.Environment.Global,
            new Uri("http://localhost:7777"), (_, _) =>
            {
                if (lockSession)
                    unlocked = false;
                else
                    File.WriteAllText(path, Seal());
                return Task.FromResult(new MintedPlaceholder("test-placeholder"));
            },
            tokens => { revoked.AddRange(tokens); return Task.CompletedTask; }, default, () => unlocked));

        Assert.That(error!.Message, Does.Contain(lockSession ? "unlock session changed" : "sealed environment changed"));
        Assert.That(revoked, Is.EqualTo(new[] { "test-placeholder" }));
    }

    [Test]
    public void Command_delivery_checks_the_approved_store_before_minting()
    {
        File.WriteAllText(path, Seal());
        var snapshot = file.ReadForDelivery(hello);
        File.Delete(path);
        Assert.ThrowsAsync<EnvironmentIntegrityException>(() => snapshot.DeliverAsync(snapshot.Environment.Global, new Uri("http://localhost:7777"),
            (_, _) => throw new AssertionException("Unexpected mint"), _ => throw new AssertionException("Unexpected revocation"), default));
    }
}
