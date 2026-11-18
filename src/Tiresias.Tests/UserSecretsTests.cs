using System.Collections.Immutable;
using System.Text.Json.Nodes;
using Tiresias.Extensions.Configuration;
using Tiresias.Protocol;
using Tiresias.Extensions.Configuration.Generator;
using Tiresias.UserSecrets;
using Tiresias.Vault;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using NSec.Cryptography;

namespace Tiresias.Tests;

public class SecretsFileTests
{
    [TestCase(null, SecretsFileKind.None)]
    [TestCase("  ", SecretsFileKind.None)]
    [TestCase("""{ "A": "1" }""", SecretsFileKind.Plain)]
    [TestCase("""{ "A": "1", /* VS writes comments */ }""", SecretsFileKind.Plain)]
    [TestCase("""{ "$tiresias": { "v": 1, "sealed": "AA==" } }""", SecretsFileKind.Sealed)]
    [TestCase("""{ "$tiresias": { "v": 1, "sealed": "AA==" }, "Added": "later" }""", SecretsFileKind.Sealed)]
    [TestCase("""[1, 2]""", SecretsFileKind.Invalid)]
    [TestCase("not json", SecretsFileKind.Invalid)]
    public void Classifies(string? json, SecretsFileKind kind) =>
        Assert.That(SecretsFile.Classify(json), Is.EqualTo(kind));
}

public class UserSecretsVaultTests
{
    const string Id = "6b8e0c4e-test";

    static readonly X25519KeyWrapper Tpm = X25519KeyWrapper.ForKey("tpm", Key.Create(KeyAgreementAlgorithm.X25519));

    const string Plain = """
        {
          "ConnectionStrings": { "Default": "Server=db;Password=hunter2" },
          "Hosts": [ "a", "b" ],
          "OpenAI:ApiKey": "sk-123"
        }
        """;

    [Test]
    public void Plain_file_lists_every_key_as_plaintext_to_seal()
    {
        var load = UserSecretsVault.Open(Id, Plain, Tpm);
        Assert.That(load.Keys, Is.EqualTo(new[] { "ConnectionStrings:Default", "Hosts:0", "Hosts:1", "OpenAI:ApiKey" }));
        Assert.That(load.NeedsSealing, Is.True);
        Assert.That(load.Version, Is.Zero);
    }

    [Test]
    public void Sealing_keeps_the_structure_and_leaves_no_value_in_the_file()
    {
        var sealedText = UserSecretsVault.Seal(Id, 1, UserSecretsVault.Open(Id, Plain, Tpm).Document, [Tpm]);

        Assert.That(SecretsFile.Classify(sealedText), Is.EqualTo(SecretsFileKind.Sealed));
        Assert.That(sealedText, Does.Not.Contain("hunter2").And.Not.Contain("ConnectionStrings"));

        var reopened = UserSecretsVault.Open(Id, sealedText, Tpm);
        Assert.That(reopened.NeedsSealing, Is.False);
        Assert.That(reopened.Version, Is.EqualTo(1));
        Assert.That((string?)reopened.Document["ConnectionStrings"]!["Default"], Is.EqualTo("Server=db;Password=hunter2"));
        Assert.That(reopened.Document["Hosts"]!.AsArray(), Has.Count.EqualTo(2));
    }

    [Test]
    public void Keys_added_beside_the_envelope_win_and_are_flagged_for_sealing()
    {
        var sealedText = UserSecretsVault.Seal(Id, 1, UserSecretsVault.Open(Id, Plain, Tpm).Document, [Tpm]);
        var file = JsonNode.Parse(sealedText)!.AsObject();
        file["ConnectionStrings"] = new JsonObject { ["Default"] = "Server=new" };
        file["Extra"] = "x";

        var load = UserSecretsVault.Open(Id, file.ToJsonString(), Tpm);

        Assert.That(load.PlaintextKeys, Is.EquivalentTo(new[] { "ConnectionStrings:Default", "Extra" }));
        Assert.That((string?)load.Document["ConnectionStrings"]!["Default"], Is.EqualTo("Server=new"));
        Assert.That((string?)load.Document["OpenAI:ApiKey"], Is.EqualTo("sk-123"));
    }

    [Test]
    public void A_sealed_file_copied_into_another_secrets_folder_does_not_open()
    {
        var sealedText = UserSecretsVault.Seal(Id, 1, new JsonObject { ["A"] = "1" }, [Tpm]);
        Assert.Throws<InvalidDataException>(() => UserSecretsVault.Open("other-project", sealedText, Tpm));
    }

    [Test]
    public void Another_key_cannot_open_it()
    {
        var sealedText = UserSecretsVault.Seal(Id, 1, new JsonObject { ["A"] = "1" }, [Tpm]);
        var stranger = X25519KeyWrapper.ForKey("tpm", Key.Create(KeyAgreementAlgorithm.X25519));
        Assert.Throws<InvalidDataException>(() => UserSecretsVault.Open(Id, sealedText, stranger));
    }

    [Test]
    public void Merge_replaces_arrays_rather_than_interleaving_them()
    {
        var target = new JsonObject { ["Hosts"] = new JsonArray("a", "b", "c") };
        UserSecretsVault.Merge(target, new JsonObject { ["Hosts"] = new JsonArray("z") });
        Assert.That(UserSecretsVault.FlattenKeys(target), Is.EqualTo(new[] { "Hosts:0" }));
    }
}

public class ProtectedUserSecretsProviderTests
{
    sealed class FakeAgent(AgentReply? reply) : IUserSecretsAgent
    {
        public int Calls { get; private set; }

        public AgentReply? TryLoad(AgentRequest request)
        {
            Calls++;
            return reply;
        }
    }

    string root = null!;
    string directory = null!;

    [SetUp]
    public void SetUp()
    {
        root = Path.Combine(Path.GetTempPath(), "tir-us-" + Guid.NewGuid().ToString("N"));
        directory = Path.Combine(root, "UserSecrets", "test-id");
        Directory.CreateDirectory(directory);
    }

    [TearDown]
    public void TearDown() => Directory.Delete(root, recursive: true);

    IConfigurationRoot Build(IUserSecretsAgent agent, IConfigurationBuilder? builder = null) =>
        (builder ?? new ConfigurationBuilder()).AddProtectedUserSecrets("test-id", directory, optional: false, agent).Build();

    void WriteFile(string json) => File.WriteAllText(Path.Combine(directory, SecretsFile.FileName), json);

    [Test]
    public void No_file_asks_nobody_and_yields_nothing()
    {
        var agent = new FakeAgent(new AgentReply(AgentStatus.Ok, """{ "A": "1" }"""));
        Assert.That(Build(agent).AsEnumerable(), Is.Empty);
        Assert.That(agent.Calls, Is.Zero);
    }

    [Test, NonParallelizable]
    public void Secrets_from_the_agent_say_so_in_one_line_without_values_and_a_plain_load_says_nothing()
    {
        var notices = new StringWriter();
        var before = ProtectedUserSecretsProvider.Notices;
        ProtectedUserSecretsProvider.Notices = notices;
        try
        {
            WriteFile("""{ "A": "1" }""");
            Build(new FakeAgent(null));
            Assert.That(notices.ToString(), Is.Empty);

            Build(new FakeAgent(new AgentReply(AgentStatus.Ok, """{ "A": "secret-a", "B": { "C": "secret-c" } }""")));
            Assert.That(notices.ToString().Trim(), Is.EqualTo("Tiresias: user secrets 'test-id' provided (2 keys)."));
        }
        finally
        {
            ProtectedUserSecretsProvider.Notices = before;
        }
    }

    [Test]
    public void Without_an_agent_a_plain_file_naming_a_reference_fails_rather_than_pass_it_on()
    {
        WriteFile("""{ "ConnectionStrings": { "Default": "tiresias:sql/appdb/read" } }""");
        Assert.That(() => Build(new FakeAgent(null)), Throws.InvalidOperationException.With.Message.Contains("only the Tiresias app can fetch"));
    }

    sealed class SequenceAgent(params AgentReply[] replies) : IUserSecretsAgent
    {
        int next;
        public int Calls => next;

        public AgentReply? TryLoad(AgentRequest request) => replies[Math.Min(next++, replies.Length - 1)];
    }

    [Test, NonParallelizable]
    public void Values_that_expire_are_loaded_again_before_they_do_and_the_reload_token_fires()
    {
        var before = (ProtectedUserSecretsProvider.Notices, ProtectedUserSecretsProvider.RenewalRetry);
        ProtectedUserSecretsProvider.Notices = new StringWriter();
        try
        {
            WriteFile("""{ "$tiresias": { "v": 1, "sealed": "AA==" } }""");
            var soon = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var agent = new SequenceAgent(
                new(AgentStatus.Ok, """{ "Db": "login-1" }""", RefreshAt: soon),
                new(AgentStatus.Ok, """{ "Db": "login-2" }"""));
            var config = Build(agent);
            using var _ = config as IDisposable;
            var reloaded = new ManualResetEventSlim();
            config.GetReloadToken().RegisterChangeCallback(_ => reloaded.Set(), null);

            Assert.That(config["Db"], Is.EqualTo("login-1"));
            Assert.That(reloaded.Wait(TimeSpan.FromSeconds(10)), Is.True, "no renewal");
            Assert.That(config["Db"], Is.EqualTo("login-2"));
            Assert.That(agent.Calls, Is.EqualTo(2));
        }
        finally
        {
            (ProtectedUserSecretsProvider.Notices, ProtectedUserSecretsProvider.RenewalRetry) = before;
        }
    }

    [Test, NonParallelizable]
    public void A_failed_renewal_keeps_the_old_values_says_so_and_tries_again()
    {
        var notices = new StringWriter();
        var before = (ProtectedUserSecretsProvider.Notices, ProtectedUserSecretsProvider.RenewalRetry);
        (ProtectedUserSecretsProvider.Notices, ProtectedUserSecretsProvider.RenewalRetry) = (TextWriter.Synchronized(notices), TimeSpan.FromMilliseconds(50));
        try
        {
            WriteFile("""{ "$tiresias": { "v": 1, "sealed": "AA==" } }""");
            var soon = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var agent = new SequenceAgent(
                new(AgentStatus.Ok, """{ "Db": "login-1" }""", RefreshAt: soon),
                new(AgentStatus.Error, Message: "the broker is down"),
                new(AgentStatus.Ok, """{ "Db": "login-2" }"""));
            var config = Build(agent);
            using var _ = config as IDisposable;
            var reloaded = new ManualResetEventSlim();
            config.GetReloadToken().RegisterChangeCallback(_ => reloaded.Set(), null);

            Assert.That(reloaded.Wait(TimeSpan.FromSeconds(10)), Is.True, "no renewal after the retry");
            Assert.That(config["Db"], Is.EqualTo("login-2"));
            Assert.That(notices.ToString(), Does.Contain("could not renew user secrets 'test-id'").And.Contain("the broker is down"));
        }
        finally
        {
            (ProtectedUserSecretsProvider.Notices, ProtectedUserSecretsProvider.RenewalRetry) = before;
        }
    }

    [Test]
    public void Without_an_agent_a_plain_file_loads_like_stock_user_secrets()
    {
        WriteFile("""{ "ConnectionStrings": { "Default": "x" } }""");
        Assert.That(Build(new FakeAgent(null))["ConnectionStrings:Default"], Is.EqualTo("x"));
    }

    [Test]
    public void Without_an_agent_a_sealed_file_fails_loudly()
    {
        WriteFile("""{ "$tiresias": { "v": 1, "sealed": "AA==" } }""");
        Assert.That(() => Build(new FakeAgent(null)), Throws.InvalidOperationException.With.Message.Contains("tir agent"));
    }

    [Test]
    public void With_an_agent_its_document_is_what_loads()
    {
        WriteFile("""{ "$tiresias": { "v": 1, "sealed": "AA==" } }""");
        var config = Build(new FakeAgent(new AgentReply(AgentStatus.Ok, """{ "Db": { "Password": "p" } }""")));
        Assert.That(config["Db:Password"], Is.EqualTo("p"));
        Assert.That(config["$tiresias:sealed"], Is.Null);
    }

    [Test]
    public void A_refused_consent_stops_the_app()
    {
        WriteFile("""{ "A": "1" }""");
        Assert.That(() => Build(new FakeAgent(new AgentReply(AgentStatus.Denied))), Throws.InvalidOperationException.With.Message.Contains("denied"));
    }

    [Test]
    public void Replaces_the_stock_source_where_it_stands()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Before"] = "1" })
            .AddJsonFile(new PhysicalFileProvider(directory), SecretsFile.FileName, optional: true, reloadOnChange: false)
            .AddInMemoryCollection(new Dictionary<string, string?> { ["After"] = "1" });

        builder.AddProtectedUserSecrets("test-id", directory, optional: false, new FakeAgent(null));

        Assert.That(builder.Sources, Has.Count.EqualTo(3));
        Assert.That(builder.Sources[1].GetType().Name, Is.EqualTo("ProtectedUserSecretsSource"));
    }

    [Test]
    public void ProtectUserSecrets_swaps_what_a_host_builder_added()
    {
        var builder = new ConfigurationBuilder()
            .AddJsonFile(new PhysicalFileProvider(directory), SecretsFile.FileName, optional: true, reloadOnChange: false);
        builder.ProtectUserSecrets();
        Assert.That(builder.Sources.Single().GetType().Name, Is.EqualTo("ProtectedUserSecretsSource"));
    }
}

public class UserSecretsInterceptorTests
{
    [Test]
    public void This_assemblys_own_AddUserSecrets_call_is_rerouted()
    {
        // Compiled with the generator as an analyzer, so this very call site is intercepted.
        var builder = new ConfigurationBuilder().AddUserSecrets("tir-test-" + Guid.NewGuid().ToString("N"));
        Assert.That(builder.Sources.Single().GetType().Name, Is.EqualTo("ProtectedUserSecretsSource"));
    }

    [Test]
    public void A_web_host_builders_own_user_secrets_are_swapped_too()
    {
        // The project sets a UserSecretsId, so Development makes CreateBuilder add the stock source
        // from inside the framework; the intercepted call site swaps it afterwards. The stock source
        // only points at the secrets folder when that folder exists (with no folder there is nothing
        // to protect), so the test makes an empty one.
        var assembly = typeof(UserSecretsInterceptorTests).Assembly;
        var id = assembly.GetCustomAttributes(typeof(Microsoft.Extensions.Configuration.UserSecrets.UserSecretsIdAttribute), false)
            .Cast<Microsoft.Extensions.Configuration.UserSecrets.UserSecretsIdAttribute>().Single().UserSecretsId;
        var folder = Path.GetDirectoryName(Microsoft.Extensions.Configuration.UserSecrets.PathHelper.GetSecretsPathFromSecretsId(id))!;
        var created = !Directory.Exists(folder);
        Directory.CreateDirectory(folder);
        try
        {
            var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(new Microsoft.AspNetCore.Builder.WebApplicationOptions
            {
                EnvironmentName = "Development",
                ApplicationName = assembly.GetName().Name,
            });
            var sources = ((IConfigurationBuilder)builder.Configuration).Sources;
            Assert.That(sources.Select(s => s.GetType().Name), Has.One.EqualTo("ProtectedUserSecretsSource"));
            Assert.That(sources.OfType<Microsoft.Extensions.Configuration.Json.JsonConfigurationSource>().Where(s => s.Path == SecretsFile.FileName), Is.Empty);
        }
        finally
        {
            if (created)
                Directory.Delete(folder);
        }
    }

    [Test]
    public void Generated_interceptors_compile_for_every_overload()
    {
        const string source = """
            using Microsoft.Extensions.Configuration;
            public class P
            {
                public static void Main()
                {
                    var b = new ConfigurationBuilder();
                    b.AddUserSecrets<P>();
                    b.AddUserSecrets<P>(optional: true);
                    b.AddUserSecrets<P>(true, false);
                    b.AddUserSecrets(typeof(P).Assembly);
                    b.AddUserSecrets(typeof(P).Assembly, true);
                    b.AddUserSecrets("id");
                    b.AddUserSecrets("id", false);
                }
            }
            """;
        var parse = new CSharpParseOptions(LanguageVersion.Preview)
            .WithFeatures([new("InterceptorsNamespaces", "Tiresias.Generated")]);
        var references = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => !a.IsDynamic && a.Location.Length > 0)
            .Select(a => MetadataReference.CreateFromFile(a.Location))
            .Append(MetadataReference.CreateFromFile(typeof(UserSecretsConfigurationExtensions).Assembly.Location))
            .Append(MetadataReference.CreateFromFile(typeof(ProtectedUserSecretsExtensions).Assembly.Location));
        var compilation = CSharpCompilation.Create("app", [CSharpSyntaxTree.ParseText(source, parse)], references,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication));

        var driver = CSharpGeneratorDriver.Create([new UserSecretsInterceptorGenerator().AsSourceGenerator()], parseOptions: parse);
        driver.RunGeneratorsAndUpdateCompilation(compilation, out var output, out var generatorDiagnostics);

        Assert.That(generatorDiagnostics, Is.Empty);
        var errors = output.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToImmutableArray();
        Assert.That(errors, Is.Empty, string.Join("\n", errors));
        var generated = output.SyntaxTrees.Last().ToString();
        Assert.That(generated.Split("InterceptsLocationAttribute(1,").Length - 1, Is.EqualTo(7), generated);
    }
}
