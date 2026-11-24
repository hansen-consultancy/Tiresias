using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tiresias.AdminTier;
using Tiresias.Client;
using Tiresias.GitHub;
using Tiresias.Policy;
using Tiresias.Protocol;
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

    [Test]
    public void A_handed_out_sql_login_goes_in_the_connection_string_variable()
    {
        var env = ExecPlan.Environment([new(Svc("appdb", "mssql://db.example/AppDb"), "tirph_db", "Server=db.example;User ID=tir_x_read;Password=t")], Forwarder);
        Assert.That(env["APPDB_CONNECTION_STRING"], Is.EqualTo("Server=db.example;User ID=tir_x_read;Password=t"));
    }

    static Grant SqlGrant(string name, bool logins, bool elevation = false) =>
        new(name, name, new(new HashSet<string>(), []), RequiresElevation: elevation, IssuesLogins: logins);

    [Test]
    public void The_login_grant_is_the_most_privileged_one_that_issues_logins_without_elevation()
    {
        var db = new Service("appdb", new Uri("mssql://db.example/AppDb"), [SqlGrant("read", true), SqlGrant("write", true), SqlGrant("admin", true, elevation: true)]);
        Assert.That(ExecPlan.LoginGrant(db, ceiling: null)?.Name, Is.EqualTo("write"));
        Assert.That(ExecPlan.LoginGrant(db, ceiling: "read")?.Name, Is.EqualTo("read"));
        Assert.That(ExecPlan.LoginGrant(db with { Grants = [SqlGrant("read", false)] }, null), Is.Null);
        Assert.That(ExecPlan.LoginGrant(db with { Upstream = new Uri("https://db.example/") }, null), Is.Null);
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
        public bool? HelloBound { get; set; }
        public Task<bool?> HelloBoundAsync() => Task.FromResult(HelloBound);
        public BrokerServiceState BrokerService { get; set; }
        public DoctorVault? Vault { get; set; } = new(2, [], []);
        public int? BrokerStatus { get; set; } = 401;
        public bool Forwarder { get; set; } = true;
        public List<DoctorFile> Secrets { get; } = [];
        public List<DoctorFile> ProjectFiles { get; } = [];
        public List<DoctorFile> Config { get; } = [];
        public List<string> Keys { get; } = [];
        public DoctorDecoys? Decoys { get; set; }
        public List<string> Blocked { get; } = [];
        public List<DecoyUseRecord> Uses { get; } = [];
        public bool IncidentsUnavailable { get; set; }
        public IEnumerable<string> BlockedPrograms() => Blocked;
        public IEnumerable<DecoyUseRecord> DecoyUses() => IncidentsUnavailable ? throw new IOException() : Uses;

        public Task<int?> BrokerStatusAsync() => Task.FromResult(BrokerStatus);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(Forwarder);
        public IEnumerable<DoctorFile> UserSecretsFiles() => Secrets;
        public IEnumerable<DoctorFile> Projects() => ProjectFiles;
        public IEnumerable<DoctorFile> ConfigFiles() => Config;
        public IEnumerable<string> KeyFiles() => Keys;
        public List<DoctorRavenCertificate> Raven { get; } = [];
        public List<string> ClearanceAsked { get; } = [];
        public IEnumerable<DoctorRavenCertificate> RavenCertificates() => Raven;

        public Task<DoctorBrokerAnswer?> RavenClearanceAsync(string service)
        {
            ClearanceAsked.Add(service);
            return Task.FromResult<DoctorBrokerAnswer?>(new(200, System.Text.Encoding.UTF8.GetBytes("""{"clearance":"Operator","databases":{}}""")));
        }
        public AdminTierFacts? AdminTier { get; set; }
    }

    [Test]
    public async Task An_unavailable_incident_history_is_reported_alongside_the_other_checks()
    {
        var checks = await Doctor.RunAsync(new FakeProbe { IncidentsUnavailable = true });
        Assert.That(checks.Any(c => c.Name == "decoy incidents and program blocks" && c.Status == DoctorStatus.Warn), Is.True);
        Assert.That(checks.Any(c => c.Name == Doctor.VariablesCheck), Is.True);
    }

    static AdminStatusResult Answer(string version) => new(version, AdminWire.ProtocolVersion, new());

    [Test]
    public async Task The_admin_tier_has_a_line_only_when_installed_and_fails_when_stopped()
    {
        Assert.That((await Doctor.RunAsync(new FakeProbe())).Any(c => c.Name == Doctor.AdminTierCheck), Is.False);
        Assert.That((await Doctor.RunAsync(new FakeProbe { AdminTier = new(false, false, null, "0.3.0") })).Any(c => c.Name == Doctor.AdminTierCheck), Is.False);

        async Task<DoctorCheck> Line(AdminTierFacts facts) =>
            (await Doctor.RunAsync(new FakeProbe { AdminTier = facts })).Single(c => c.Name == Doctor.AdminTierCheck);

        var running = await Line(new(true, true, Answer("0.3.0"), "0.3.0"));
        Assert.That(running.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(running.Detail, Does.Contain("0.3.0").And.Contain("none yet"));
        Assert.That((await Line(new(true, false, null, "0.3.0"))).Status, Is.EqualTo(DoctorStatus.Fail));
        Assert.That((await Line(new(true, true, null, "0.3.0"))).Status, Is.EqualTo(DoctorStatus.Fail));
        var older = await Line(new(true, true, Answer("0.2.1"), "0.3.0"));
        Assert.That(older.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(older.Detail, Does.Contain("Update"));
    }

    [Test]
    public async Task Decoys_say_whether_a_use_would_be_seen()
    {
        Assert.That((await Doctor.RunAsync(new FakeProbe())).Any(c => c.Name == "decoys"), Is.False);

        var listening = (await Doctor.RunAsync(new FakeProbe { Decoys = new(2, true) })).Single(c => c.Name == "decoys");
        var deaf = (await Doctor.RunAsync(new FakeProbe { Decoys = new(2, false) })).Single(c => c.Name == "decoys");

        Assert.That(listening.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(deaf.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(deaf.Detail, Does.Contain("goes unseen"));
    }

    [Test]
    public async Task Decoys_held_by_the_admin_tier_count_it_as_the_listener()
    {
        var held = (await Doctor.RunAsync(new FakeProbe { Decoys = new(2, true, Held: true) })).Single(c => c.Name == "decoys");
        var portTaken = (await Doctor.RunAsync(new FakeProbe { Decoys = new(2, false, Held: true) })).Single(c => c.Name == "decoys");

        Assert.That(held.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(held.Detail, Does.Contain("admin tier").And.Not.Contain("tir agent"));
        Assert.That(portTaken.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(portTaken.Detail, Does.Contain("admin tier").And.Not.Contain("start the app"));
    }

    [Test]
    public async Task A_program_blocked_for_a_decoy_is_that_finding_not_this_wasnt_mes()
    {
        const string evil = @"C:\Temp\evil.exe", other = @"C:\Temp\other.exe";
        var probe = new FakeProbe();
        probe.Blocked.AddRange([evil, other]);
        probe.Uses.Add(new(evil, "the decoy API key", DateTimeOffset.UtcNow));

        var checks = await Doctor.RunAsync(probe);

        Assert.That(checks.Where(c => c.Kind == Doctor.DecoyKind).Select(c => c.Subject), Is.EqualTo(new[] { evil }));
        Assert.That(checks.Where(c => c.Kind == Doctor.BlockedKind).Select(c => c.Fix), Is.EqualTo(new DoctorFix[] { new RevealFile(other) }));
    }

    static readonly Position Plaintext = new(Exposure.Readable, Control.Silent);
    static readonly Position SealedApproved = new(Exposure.Sealed, Control.Approved);
    static readonly string Root = Path.Combine(Path.GetTempPath(), "doctor-projects");

    static async Task<DoctorCheck> Check(FakeProbe probe, string namePrefix) =>
        (await Doctor.RunAsync(probe)).Single(c => c.Name.StartsWith(namePrefix, StringComparison.Ordinal));

    [Test]
    public async Task A_healthy_machine_is_all_ok()
    {
        var checks = await Doctor.RunAsync(new FakeProbe());
        Assert.That(checks.Select(c => c.Status), Is.All.EqualTo(DoctorStatus.Ok));
        Assert.That(checks.Select(c => c.Name), Is.EqualTo(new[] { "broker pinned", "device key", "recovery key", "vault", "broker reachable", "forwarder", "environment variables", Doctor.KeysAsValuesCheck }));
    }

    [Test]
    public async Task RavenDB_clearance_is_asked_through_a_broker_that_answers()
    {
        var probe = new FakeProbe { Raven = { new("orders", null, null, null) } };
        Assert.That((await Check(probe, "RavenDB clearance")).Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(probe.ClearanceAsked, Is.EqualTo(new[] { "orders" }));
    }

    [Test]
    public async Task RavenDB_clearance_is_skipped_without_waiting_on_a_broker_that_doesnt()
    {
        var probe = new FakeProbe { BrokerStatus = null, Raven = { new("orders", null, null, null) } };
        Assert.That((await Check(probe, "RavenDB clearance")).Detail, Does.StartWith("skipped"));
        Assert.That(probe.ClearanceAsked, Is.Empty);
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
    public async Task A_device_whose_hello_key_isnt_in_the_chain_is_told_to_bind_it()
    {
        var unbound = await Check(new FakeProbe { HelloBound = false }, "trust chain");
        Assert.That(unbound.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(unbound.Detail, Does.Contain("tir trust bind-hello"));
        Assert.That((await Check(new FakeProbe { HelloBound = true }, "trust chain")).Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That((await Doctor.RunAsync(new FakeProbe())).Select(c => c.Name), Does.Not.Contain("trust chain"), "no chain to read");
    }

    [Test]
    public async Task The_broker_process_line_follows_the_service()
    {
        Assert.That((await Check(new FakeProbe { Solo = true, BrokerService = BrokerServiceState.Running }, "broker process")).Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That((await Check(new FakeProbe { Solo = true, BrokerService = BrokerServiceState.Stopped }, "broker process")).Status, Is.EqualTo(DoctorStatus.Fail));
        Assert.That((await Check(new FakeProbe { Solo = true }, "broker process")).Detail, Does.Contain("tir solo service install"));
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

    [Test]
    public async Task Unbound_secrets_fail_and_name_the_migration()
    {
        var vault = await Check(new FakeProbe { Vault = new(3, [], [], ["llm-read"]) }, "vault");
        Assert.That(vault.Status, Is.EqualTo(DoctorStatus.Fail));
        Assert.That(vault.Detail, Does.Contain("llm-read").And.Contain("tir vault migrate"));
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
    public async Task Developer_checks_and_solo_notes_are_marked()
    {
        var probe = new FakeProbe { Solo = true };
        probe.Secrets.Add(new(@"C:\u\abc\secrets.json", """{"ApiKey":"sk-live-1"}"""));
        var checks = await Doctor.RunAsync(probe);

        Assert.Multiple(() =>
        {
            Assert.That(checks.Single(c => c.Name.StartsWith("user secrets", StringComparison.Ordinal)).ForDevelopers, Is.True);
            Assert.That(checks.Where(c => c.SoloNote).Select(c => c.Name), Is.EquivalentTo(new[] { "egress", "isolation" }));
            Assert.That(checks.Where(c => c.Name is "broker pinned" or "mode" or Doctor.VariablesCheck).Any(c => c.ForDevelopers), Is.False);
        });
    }

    [Test]
    public async Task A_plaintext_secrets_file_warns_with_its_id_and_key_count_and_never_its_keys_or_values()
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new(@"C:\u\abc\secrets.json", """{"ConnectionStrings":{"Db":"Password=hunter2"},"ApiKey":"sk-live-1"}"""));
        var check = await Check(probe, "user secrets");

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Fix, Is.EqualTo(new ReviewUserSecrets("abc")));
        Assert.That((check.Now, check.Better), Is.EqualTo((Plaintext, SealedApproved)));
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

    [Test]
    public async Task A_secrets_file_of_settings_only_is_an_ok_line_not_a_finding()
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new(@"C:\u\abc\secrets.json", """{"Feature":{"Enabled":true},"Api":"https://api.example.com"}"""));
        var check = await Check(probe, "user secrets");

        Assert.That((check.Status, check.IsFinding), Is.EqualTo((DoctorStatus.Ok, false)));
        Assert.That(check.Detail, Does.Contain("settings, not secrets").And.Contain("2 keys").And.Not.Contain("example"));
    }

    [Test]
    public async Task Dismissing_a_plaintext_secrets_file_lapses_when_a_key_is_added()
    {
        static async Task<DoctorCheck> For(string text)
        {
            var probe = new FakeProbe();
            probe.Secrets.Add(new(@"C:\u\abc\secrets.json", text));
            return await Check(probe, "user secrets");
        }
        var dismissals = Dismissals.Empty.Dismiss(await For("""{"ApiKey":"a"}"""), "test key", DateTimeOffset.UnixEpoch);

        Assert.That(dismissals.For(await For("""{"ApiKey":"changed"}""")), Is.Not.Null, "a new value is not a new finding");
        Assert.That(dismissals.For(await For("""{"ApiKey":"a","Other":"b"}""")), Is.Null, "a new key is");
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
        Assert.That(projects[0].Fix, Is.EqualTo(new ReferenceConfigurationPackage("bare.csproj")));
        Assert.That(projects[0].Fix!.Instruction, Is.EqualTo("dotnet add \"bare.csproj\" package Tiresias.Extensions.Configuration"));
    }

    [Test]
    public async Task Lines_about_Tiresias_itself_are_not_findings()
    {
        var checks = await Doctor.RunAsync(new FakeProbe { RecoveryKeySet = false, BrokerStatus = null });
        Assert.That(checks.Where(c => c.IsFinding), Is.Empty);
    }

    [Test]
    public async Task Exposed_variables_are_a_finding_whose_fix_protects_exactly_them()
    {
        var check = (await Doctor.RunAsync(new FakeProbe { ExposedVariables = ["OPENAI_API_KEY", "HF_TOKEN"] })).Single(c => c.Name == Doctor.VariablesCheck);
        Assert.That(check.Fix, Is.EqualTo(new ProtectVariables(["OPENAI_API_KEY", "HF_TOKEN"])));
        Assert.That(check.Fix!.Instruction, Is.EqualTo("tir env protect OPENAI_API_KEY HF_TOKEN"));
        Assert.That(check.Now.ToString(), Is.EqualTo("E5/C3"));
        Assert.That(check.Better.ToString(), Is.EqualTo("E4/C1"));
    }

    static async Task<DoctorCheck[]> ConnectionStrings(FakeProbe probe) =>
        [.. (await Doctor.RunAsync(probe)).Where(c => c.Name.StartsWith("connection string", StringComparison.Ordinal))];

    static DoctorFile AppSettings(string json) => new(Path.Combine(Root, "Api", "appsettings.json"), json);

    [TestCase("Data Source=tcp:db.example.com,1433;Initial Catalog=Orders;User ID=app;Password=hunter2;TrustServerCertificate=True", "tcp:db.example.com,1433", true)]
    [TestCase("server=db.example.com;database=Orders;uid=app;pwd=hunter2;MultipleActiveResultSets=true", "db.example.com", true)]
    [TestCase("Server=db.example.com;Database=Orders;User Id=app;Password=hunter2;Encrypt=True", "db.example.com", true)]
    [TestCase("Server=db.example.com;Database=Orders;User Id=app;Password=hunter2", "db.example.com", false)]
    [TestCase("Server=db.example.com;Database=Orders;User=app;Password=hunter2;Application Name=Jobs;Encrypt=False", "db.example.com", false)]
    [TestCase("Server = db.example.com; Database = Orders; User Id = app; Password = hunter2; Encrypt = True", "db.example.com", true)]
    public async Task A_sql_server_password_in_appsettings_is_a_finding_offering_a_login_per_lease(string connectionString, string server, bool certain)
    {
        var probe = new FakeProbe();
        probe.Config.Add(AppSettings($$$"""{"ConnectionStrings":{"Default":"{{{connectionString}}}"}}"""));
        var check = (await ConnectionStrings(probe)).Single();

        Assert.That(check.Name, Is.EqualTo($"connection string ConnectionStrings:Default in {Path.Combine(Root, "Api", "appsettings.json")}"));
        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Fix, Is.EqualTo(new SetUpSqlServer(server, "Orders")));
        Assert.That((check.Now, check.Better), Is.EqualTo((Plaintext, new Position(Exposure.ShortLived, Control.Approved))));
        Assert.That(check.Detail + check.Fix!.Instruction, Does.Not.Contain("hunter2"));
        // MySQL takes User Id too, so one keyword SQL Server shares with others isn't enough to say so.
        Assert.That(check.Detail.Contains("If this is SQL Server", StringComparison.Ordinal), Is.EqualTo(!certain));
    }

    [TestCase("Host=pg.example.com;Database=Orders;Username=app;Password=hunter2")]
    [TestCase("Host=pg.example.com;Username=app;Password=hunter2;Trust Server Certificate=true")]
    [TestCase("Server=my.example.com;Database=Orders;User Id=app;Password=hunter2;SslMode=Required")]
    [TestCase("Server=my.example.com;Database=Orders;User Id=app;Password=hunter2;CharSet=utf8mb4")]
    [TestCase("Data Source=app.db;Encrypt=True;Password=hunter2")]
    [TestCase("Server=my.example.com;Port=3306;Database=Orders;Uid=app;Pwd=hunter2")]
    [TestCase("Data Source=db.example.com/ORCL;User Id=app;Password=hunter2")]
    [TestCase("Password=hunter2")]
    public async Task A_password_for_another_kind_of_server_is_a_finding_without_a_login_to_offer(string connectionString)
    {
        var probe = new FakeProbe();
        probe.Config.Add(AppSettings($$"""{"Db":"{{connectionString}}"}"""));
        var check = (await ConnectionStrings(probe)).Single();

        Assert.That(check.Fix, Is.Null);
        Assert.That((check.Now, check.Better), Is.EqualTo((Plaintext, SealedApproved)));
        Assert.That(check.Detail, Does.Contain("SQL Server only").And.Not.Contain("hunter2"));
    }

    [TestCase("""{"ConnectionStrings":{"Default":"Server=db;Database=Orders;Integrated Security=true"}}""")]
    [TestCase("""{"ConnectionStrings":{"Default":"Server=db;Database=Orders;User Id=app;Password="}}""")]
    [TestCase("""{"ConnectionStrings":{"Default":"tiresias:sql/orders/read"}}""")]
    [TestCase("""{"Smtp":{"Password":"hunter2"}}""")]
    [TestCase("""{"Note":"set password= in the portal"}""")]
    [TestCase("{ not json")]
    public async Task Configuration_without_a_password_in_a_connection_string_has_no_such_finding(string json)
    {
        var probe = new FakeProbe();
        probe.Config.Add(AppSettings(json));
        Assert.That(await ConnectionStrings(probe), Is.Empty);
    }

    [Test]
    public async Task A_connection_string_in_user_secrets_is_found_in_plain_files_and_beside_sealed_ones()
    {
        var probe = new FakeProbe();
        probe.Secrets.Add(new(Path.Combine(Root, "plain-id", "secrets.json"), """{"ConnectionStrings":{"Db":"Server=db;User Id=app;Password=hunter2"}}"""));
        probe.Secrets.Add(new(Path.Combine(Root, "sealed-id", "secrets.json"), """{"$tiresias":{"v":1,"sealed":"AQID"},"Cs":"Server=db;User Id=app;Password=hunter2"}"""));
        var names = (await ConnectionStrings(probe)).Select(c => c.Name);
        Assert.That(names, Is.EqualTo(new[] { "connection string ConnectionStrings:Db in user secrets plain-id", "connection string Cs in user secrets sealed-id" }));
    }

    [Test]
    public async Task A_key_file_named_for_ravendb_offers_the_broker_presenting_it()
    {
        var path = Path.Combine(Root, "Api", "raven-client.pfx");
        var probe = new FakeProbe();
        probe.Keys.Add(path);
        var check = await Check(probe, "certificate");

        Assert.That(check.Fix, Is.EqualTo(new SetUpRaven(path)));
        Assert.That((check.Now, check.Better), Is.EqualTo((Plaintext, new Position(Exposure.BrokerOnly, Control.Approved))));
    }

    [Test]
    public async Task Any_other_key_file_is_a_finding_without_a_fix_to_start()
    {
        var probe = new FakeProbe();
        probe.Keys.Add(Path.Combine(Root, "signing.pfx"));
        var check = await Check(probe, "certificate");

        Assert.That(check.Fix, Is.Null);
        Assert.That(check.IsFinding);
        Assert.That(check.Detail, Does.Contain("RavenDB").And.Contain("non-exportable"));
    }

    [Test]
    public async Task A_key_file_ravendb_configuration_points_at_is_one_finding_naming_the_key()
    {
        var path = Path.Combine(Root, "Api", "certs", "client.pfx");
        var probe = new FakeProbe();
        probe.Config.Add(AppSettings("""{"RavenDb":{"CertificatePath":"certs/client.pfx"}}"""));
        probe.Keys.Add(path);
        var check = await Check(probe, "certificate");

        Assert.That(check.Name, Is.EqualTo($"certificate {path}"));
        Assert.That(check.Fix, Is.EqualTo(new SetUpRaven(path)));
        Assert.That(check.Detail, Does.Contain("RavenDb:CertificatePath"));
    }

    [Test]
    public async Task A_key_file_found_under_a_relative_root_still_matches_the_configuration_naming_it()
    {
        var probe = new FakeProbe();
        probe.Config.Add(new(Path.Combine("Api", "appsettings.json"), """{"RavenDb":{"CertificatePath":"certs/client.pfx"}}"""));
        probe.Keys.Add(Path.Combine(".", "Api", "certs", "client.pfx"));
        var check = await Check(probe, "certificate");

        Assert.That(check.Fix, Is.InstanceOf<SetUpRaven>());
        Assert.That(check.Detail, Does.Contain("RavenDb:CertificatePath"));
    }

    [Test]
    public async Task A_certificate_configuration_names_outside_the_scanned_folder_is_still_a_finding()
    {
        var elsewhere = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "elsewhere", "cluster.pfx"));
        var probe = new FakeProbe();
        probe.Config.Add(AppSettings($$$"""{"Raven":{"Certificate":{{{JsonSerializer.Serialize(elsewhere)}}}},"Logging":{"Certificate":"none"}}"""));
        var check = await Check(probe, "certificate");

        Assert.That(check.Fix, Is.EqualTo(new SetUpRaven(elsewhere)));
        Assert.That(check.Detail, Does.Contain("Raven:Certificate"));
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
