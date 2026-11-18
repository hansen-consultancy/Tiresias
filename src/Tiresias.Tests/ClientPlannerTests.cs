using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tiresias.Client;
using Tiresias.GitHub;
using Tiresias.Policy;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class GitHubAppJwtTests
{
    [Test]
    public void The_jwt_is_rs256_signed_by_the_app_key_with_drift_tolerant_times()
    {
        using var rsa = RSA.Create(2048);
        var now = new DateTimeOffset(2026, 11, 17, 8, 0, 0, TimeSpan.Zero);
        var jwt = GitHubAppJwt.Create("12345", rsa.ExportPkcs8PrivateKeyPem(), now);

        var parts = jwt.Split('.');
        Assert.That(parts, Has.Length.EqualTo(3));
        using var header = JsonDocument.Parse(FromBase64Url(parts[0]));
        using var payload = JsonDocument.Parse(FromBase64Url(parts[1]));
        Assert.That(header.RootElement.GetProperty("alg").GetString(), Is.EqualTo("RS256"));
        Assert.That(payload.RootElement.GetProperty("iss").GetString(), Is.EqualTo("12345"));
        Assert.That(payload.RootElement.GetProperty("iat").GetInt64(), Is.EqualTo(now.AddSeconds(-60).ToUnixTimeSeconds()));
        Assert.That(payload.RootElement.GetProperty("exp").GetInt64(), Is.EqualTo(now.AddMinutes(9).ToUnixTimeSeconds()));
        Assert.That(rsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), FromBase64Url(parts[2]),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);
        Assert.That(jwt, Does.Not.Contain("=").And.Not.Contain("+").And.Not.Contain("/"));
    }

    [TestCase("""{"appId":"1","installationId":2,"privateKeyPem":"-----BEGIN"}""", true)]
    [TestCase("""{"appId":"1","installationId":0,"privateKeyPem":"x"}""", false)]
    [TestCase("""{"appId":"","installationId":2,"privateKeyPem":"x"}""", false)]
    [TestCase("Bearer ghp_notjson", false)]
    public void Only_complete_app_json_is_a_github_app_secret(string text, bool valid) =>
        Assert.That(GitHubAppSecret.Parse(Encoding.UTF8.GetBytes(text)) is not null, Is.EqualTo(valid));

    static byte[] FromBase64Url(string s)
    {
        var b = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(b.PadRight(b.Length + (4 - b.Length % 4) % 4, '='));
    }
}

public class ExecPlanTests
{
    static readonly Uri Forwarder = new("http://127.0.0.1:7781/ignored");

    static Service Svc(string slug, string upstream) => new(slug, new Uri(upstream), []);

    [Test]
    public void Each_service_gets_a_placeholder_and_its_loopback_url_by_kind()
    {
        var env = ExecPlan.Environment(
        [
            new(Svc("llm-prod", "https://llm.example/"), "tirph_llm"),
            new(Svc("appdb", "mssql://db.example/AppDb"), "tirph_db"),
            new(Svc("gh", "https://api.github.com/"), "ghs_installation"),
        ], Forwarder);

        Assert.That(env, Is.EqualTo(new Dictionary<string, string>
        {
            ["APPDB_SQL_URL"] = "http://127.0.0.1:7781/sql/appdb",
            ["APPDB_TOKEN"] = "tirph_db",
            ["GH_TOKEN"] = "ghs_installation",
            ["GITHUB_TOKEN"] = "ghs_installation",
            ["LLM_PROD_BASE_URL"] = "http://127.0.0.1:7781/svc/llm-prod",
            ["LLM_PROD_TOKEN"] = "tirph_llm",
        }));
    }

    [TestCase("llm", "LLM")]
    [TestCase("llm-prod", "LLM_PROD")]
    [TestCase("a.b c", "A_B_C")]
    public void Env_names_are_upper_case_with_underscores(string slug, string expected) =>
        Assert.That(ExecPlan.EnvName(slug), Is.EqualTo(expected));
}

public class DoctorTests
{
    sealed class FakeProbe : IDoctorProbe
    {
        public bool Enrolled { get; set; } = true;
        public bool HasDeviceKey { get; set; } = true;
        public bool RecoveryKeySet { get; set; } = true;
        public IReadOnlyList<string> ExposedVariables { get; set; } = [];
        public bool Solo { get; set; }
        public DoctorVault? Vault { get; set; } = new(2, [], []);
        public int? BrokerStatus { get; set; } = 401;
        public bool Forwarder { get; set; } = true;
        public List<DoctorFile> Secrets { get; } = [];
        public List<DoctorFile> ProjectFiles { get; } = [];

        public Task<int?> BrokerStatusAsync() => Task.FromResult(BrokerStatus);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(Forwarder);
        public IEnumerable<DoctorFile> UserSecretsFiles() => Secrets;
        public IEnumerable<DoctorFile> Projects() => ProjectFiles;
    }

    static async Task<DoctorCheck> Check(FakeProbe probe, string namePrefix) =>
        (await Doctor.RunAsync(probe)).Single(c => c.Name.StartsWith(namePrefix, StringComparison.Ordinal));

    [Test]
    public async Task A_healthy_machine_is_all_ok()
    {
        var checks = await Doctor.RunAsync(new FakeProbe());
        Assert.That(checks.Select(c => c.Status), Is.All.EqualTo(DoctorStatus.Ok));
        Assert.That(checks.Select(c => c.Name), Is.EqualTo(new[] { "broker pinned", "device key", "recovery key", "vault", "broker reachable", "forwarder", "environment variables" }));
    }

    [Test]
    public async Task Secret_looking_environment_variables_are_a_warning_naming_them()
    {
        var check = (await Doctor.RunAsync(new FakeProbe { ExposedVariables = ["OPENAI_API_KEY", "HF_TOKEN"] }))
            .Single(c => c.Name == Doctor.VariablesCheck);
        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Detail, Does.Contain("OPENAI_API_KEY, HF_TOKEN"));
    }

    [Test]
    public async Task Solo_mode_states_its_trade_offs_and_needs_no_forwarder()
    {
        var checks = await Doctor.RunAsync(new FakeProbe { Solo = true, Forwarder = false });
        Assert.That(checks.Single(c => c.Name == "mode").Detail, Does.StartWith("Solo"));
        Assert.That(checks.Single(c => c.Name == "forwarder").Status, Is.EqualTo(DoctorStatus.Ok));
        var warnings = checks.Where(c => c.Status == DoctorStatus.Warn).Select(c => c.Detail).ToArray();
        Assert.That(warnings, Has.Some.Contains("fixed IP"));
        Assert.That(warnings, Has.Some.Contains("same machine").And.Some.Contains("admin"));
        Assert.That(warnings, Has.Some.StartsWith("Broker runs inside the app"));
    }

    [Test]
    public async Task An_unreachable_solo_broker_says_to_start_the_app() =>
        Assert.That((await Check(new FakeProbe { Solo = true, BrokerStatus = null }, "broker reachable")).Detail, Does.Contain("start the app"));

    [Test]
    public async Task No_recovery_key_or_an_unrecoverable_secret_fails()
    {
        Assert.That((await Check(new FakeProbe { RecoveryKeySet = false }, "recovery key")).Status, Is.EqualTo(DoctorStatus.Fail));
        var vault = await Check(new FakeProbe { Vault = new(3, [], ["llm-admin"]) }, "vault");
        Assert.That(vault.Status, Is.EqualTo(DoctorStatus.Fail));
        Assert.That(vault.Detail, Does.Contain("llm-admin"));
        Assert.That((await Check(new FakeProbe { Vault = new(3, ["old"], []) }, "vault")).Status, Is.EqualTo(DoctorStatus.Warn));
    }

    [TestCase(null, DoctorStatus.Fail)]
    [TestCase(401, DoctorStatus.Ok)]
    [TestCase(200, DoctorStatus.Warn)]
    public async Task The_broker_should_refuse_an_unsigned_call(int? status, DoctorStatus expected) =>
        Assert.That((await Check(new FakeProbe { BrokerStatus = status }, "broker reachable")).Status, Is.EqualTo(expected));

    [Test]
    public async Task An_unenrolled_keyring_does_not_probe_the_broker()
    {
        var checks = await Doctor.RunAsync(new FakeProbe { Enrolled = false });
        Assert.That(checks.Select(c => c.Name), Does.Not.Contain("broker reachable"));
    }

    [Test]
    public async Task A_plaintext_secrets_file_warns_with_its_id_and_key_count_and_never_its_keys_or_values()
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new(@"C:\u\abc\secrets.json", """{"ConnectionStrings":{"Db":"Password=hunter2"},"ApiKey":"sk-live-1"}"""));
        var check = await Check(probe, "user secrets");

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.UserSecretsId, Is.EqualTo("abc"));
        Assert.That(check.Detail, Does.Contain("2 keys"));
        Assert.That(check.Detail, Does.Not.Contain("hunter2").And.Not.Contain("sk-live").And.Not.Contain("ApiKey").And.Not.Contain("ConnectionStrings"));
    }

    [Test]
    public async Task A_sealed_file_with_plain_keys_beside_it_warns()
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new("s.json", $$"""{"$tiresias":{"v":1,"sealed":"{{Convert.ToBase64String([1, 2, 3])}}"},"NewKey":"plain"}"""));
        var check = await Check(probe, "user secrets");
        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Detail, Does.Contain("1 plaintext key(s)").And.Not.Contain("NewKey"));
    }

    [Test]
    public async Task A_clean_sealed_file_or_an_empty_one_or_one_without_keys_is_not_reported()
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new("a.json", $$$"""{"$tiresias":{"v":1,"sealed":"{{{Convert.ToBase64String([1])}}}"}}"""));
        probe.Secrets.Add(new("b.json", ""));
        probe.Secrets.Add(new("c.json", "{ }"));
        Assert.That((await Doctor.RunAsync(probe)).Where(c => c.Name.StartsWith("user secrets", StringComparison.Ordinal)), Is.Empty);
    }

    [TestCase("{ not json")]
    [TestCase("""["array"]""")]
    [TestCase("""{"$tiresias":{"v":9,"sealed":"AQ=="}}""")]
    public async Task An_unreadable_secrets_file_fails(string text)
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new("x.json", text));
        Assert.That((await Check(probe, "user secrets")).Status, Is.EqualTo(DoctorStatus.Fail));
    }

    [Test]
    public async Task A_project_with_user_secrets_but_without_the_protected_provider_warns()
    {
        var probe = new FakeProbe();
        probe.ProjectFiles.Add(new("bare.csproj", "<Project><PropertyGroup><UserSecretsId>abc</UserSecretsId></PropertyGroup></Project>"));
        probe.ProjectFiles.Add(new("protected.csproj", """<Project><PropertyGroup><UserSecretsId>def</UserSecretsId></PropertyGroup><ItemGroup><PackageReference Include="Tiresias.Extensions.Configuration" /></ItemGroup></Project>"""));
        probe.ProjectFiles.Add(new("none.csproj", "<Project />"));

        var projects = (await Doctor.RunAsync(probe)).Where(c => c.Name.StartsWith("project", StringComparison.Ordinal)).ToArray();
        Assert.That(projects.Select(c => c.Name), Is.EqualTo(new[] { "project bare.csproj" }));
        Assert.That(projects[0].Status, Is.EqualTo(DoctorStatus.Warn));
    }
}

public class PaperKeyTests
{
    static readonly byte[] Raw = Enumerable.Range(1, 32).Select(i => (byte)(i * 7)).ToArray();

    [Test]
    public void A_formatted_key_parses_back_however_it_is_typed()
    {
        var text = PaperKey.Format(Raw);
        Assert.That(text.Split('\n'), Has.Length.EqualTo(2));
        Assert.That(PaperKey.Parse(text), Is.EqualTo(Raw));
        Assert.That(PaperKey.Parse(text.ToLowerInvariant().Replace(' ', '-').Replace("\n", "  ", StringComparison.Ordinal)), Is.EqualTo(Raw));
    }

    [Test]
    public void Digits_read_as_the_letters_they_look_like()
    {
        var text = PaperKey.Format(Raw);
        var typed = text.Replace('O', '0').Replace('I', '1').Replace('B', '8');
        Assert.That(PaperKey.Parse(typed), Is.EqualTo(Raw));
        Assert.That(PaperKey.Confirm(["BOIL", "SIX2"], (0, 1), "8o1l", " s1x2 "), Is.True);
    }

    [TestCase("")]
    [TestCase("ABCD 1890")]
    [TestCase("ABCD EFGH")]
    public void Anything_else_is_not_a_key(string text) => Assert.That(PaperKey.Parse(text), Is.Null);

    [Test]
    public void Words_are_the_groups_of_four_in_order()
    {
        var words = PaperKey.Words(Raw);
        Assert.That(words, Has.Count.EqualTo(13));
        Assert.That(string.Join(" ", words), Is.EqualTo(PaperKey.Format(Raw).Replace('\n', ' ')));
    }

    [TestCase(0, 0, 0, 1)]
    [TestCase(5, 5, 5, 6)]
    [TestCase(9, 2, 2, 9)]
    public void A_challenge_asks_two_different_words_in_order(int first, int second, int expectedFirst, int expectedSecond)
    {
        var draws = new Queue<int>([first, second]);
        Assert.That(PaperKey.Challenge(13, _ => draws.Dequeue()), Is.EqualTo((expectedFirst, expectedSecond)));
    }

    [Test]
    public void Confirm_ignores_case_and_spaces_but_not_a_wrong_word()
    {
        var words = PaperKey.Words(Raw);
        Assert.That(PaperKey.Confirm(words, (1, 4), $" {words[1].ToLowerInvariant()}", words[4]), Is.True);
        Assert.That(PaperKey.Confirm(words, (1, 4), words[4], words[1]), Is.False);
    }

    [Test]
    public void The_signing_key_is_stable_and_not_the_recovery_key_itself()
    {
        using var a = PaperKey.SigningKey(Raw);
        using var b = PaperKey.SigningKey(Raw);
        Assert.That(a.PublicKey.Export(KeyBlobFormat.RawPublicKey), Is.EqualTo(b.PublicKey.Export(KeyBlobFormat.RawPublicKey)));

        using var recovery = Key.Import(KeyAgreementAlgorithm.X25519, Raw, KeyBlobFormat.RawPrivateKey);
        var recoveryPublic = recovery.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        Assert.That(a.PublicKey.Export(KeyBlobFormat.RawPublicKey), Is.Not.EqualTo(recoveryPublic));
        Assert.That(PaperKey.Matches(Raw, recoveryPublic), Is.True);
        Assert.That(PaperKey.Matches(Raw.Reverse().ToArray(), recoveryPublic), Is.False);
    }
}
