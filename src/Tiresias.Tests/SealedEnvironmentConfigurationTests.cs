using System.Text.Json;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;
using Tiresias.EnvironmentVariables;
using Tiresias.Extensions.Configuration;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class ConfigurationDeliveryTests
{
    static readonly string Root = OperatingSystem.IsWindows() ? @"C:\src" : "/src";
    static readonly string App = Path.Combine(Root, "shop");

    static readonly SealedEnvironment Sealed = SealedEnvironment.Empty
        .WithGlobal([new("Payments__ApiKey", "global-value"), new("OPENAI_API_KEY", "test-key"), new("UNMARKED", "x")])
        .WithFolder(App, [new("Payments__ApiKey", "folder-value")])
        .WithConfiguration("Payments__ApiKey")
        .WithConfiguration("OPENAI_API_KEY");

    [Test]
    public void Only_marked_variables_resolved_for_the_folder_are_offered()
    {
        var offered = Sealed.ForConfiguration(App, []);
        Assert.That(offered.Select(v => (v.Variable.Name, v.Variable.Value, v.Folder)), Is.EquivalentTo(new[]
        {
            ("Payments__ApiKey", "folder-value", (string?)App),
            ("OPENAI_API_KEY", "test-key", (string?)null),
        }));
    }

    [Test]
    public void A_name_the_process_already_has_is_not_offered_again() =>
        Assert.That(Sealed.ForConfiguration(App, ["payments__apikey"]).Select(v => v.Variable.Name), Is.EqualTo(new[] { "OPENAI_API_KEY" }));

    [Test]
    public void Any_name_can_be_marked_not_only_double_underscore_ones() =>
        Assert.That(Sealed.IsForConfiguration("openai_api_key"), Is.True);

    [Test]
    public void A_variable_is_either_a_placeholder_or_for_configuration()
    {
        Assert.That(() => Sealed.WithPlaceholder(new("OPENAI_API_KEY", "openai", "OPENAI_BASE_URL")), Throws.InvalidOperationException);
        var placeholder = SealedEnvironment.Empty.WithGlobal([new("OPENAI_API_KEY", "test-key")]).WithPlaceholder(new("OPENAI_API_KEY", "openai", "OPENAI_BASE_URL"));
        Assert.That(() => placeholder.WithConfiguration("OPENAI_API_KEY"), Throws.InvalidOperationException);
    }

    [Test]
    public void Marking_twice_keeps_one_mark_and_unmarking_removes_it()
    {
        Assert.That(Sealed.WithConfiguration("openai_api_key").Configuration, Has.Count.EqualTo(2));
        Assert.That(Sealed.WithoutConfiguration("OPENAI_API_KEY").IsForConfiguration("OPENAI_API_KEY"), Is.False);
    }

    [Test]
    public void The_marks_survive_the_sealed_document()
    {
        var back = SealedEnvironment.FromDocument(Sealed.ToDocument());
        Assert.That(back.Configuration, Is.EqualTo(Sealed.Configuration));
        Assert.That(SealedEnvironment.FromDocument(SealedEnvironment.Empty.WithGlobal([new("A", "b")]).ToDocument()).Configuration, Is.Empty);
    }
}

public class EnvironmentLoadTests
{
    const string Exe = @"C:\apps\shop.exe";
    static readonly X25519KeyWrapper Hello = X25519KeyWrapper.ForKey("hello", Key.Create(KeyAgreementAlgorithm.X25519));

    string root = "";
    string app = "";
    EnvironmentFile file = null!;
    Keys keys = null!;
    Screen screen = null!;
    UserSecretsService service = null!;

    sealed class Keys : IUserSecretsKeys
    {
        public bool IsUnlocked { get; set; } = true;
        public IKeyWrapper? Unlocked => IsUnlocked ? Hello : null;
        public IKeyWrapper? Recovery => null;
    }

    sealed class Screen : IUserSecretsConsentPrompt
    {
        public Queue<ConsentAnswer> Answers { get; } = new();
        public List<UserSecretsConsentRequest> Shown { get; } = [];
        public int UnlockAsked { get; private set; }

        public Task<ConsentAnswer> AskAsync(UserSecretsConsentRequest request, CancellationToken ct)
        {
            Shown.Add(request);
            return Task.FromResult(Answers.Dequeue());
        }

        public Task<bool> AskUnlockAsync(string? executable, string userSecretsId, CancellationToken ct)
        {
            UnlockAsked++;
            return Task.FromResult(false);
        }
    }

    [SetUp]
    public void SetUp()
    {
        root = Directory.CreateTempSubdirectory("tir-envload-").FullName;
        app = Path.Combine(root, "shop");
        file = new(Path.Combine(root, "environment.json"));
        keys = new();
        screen = new();
        service = new(Path.Combine(root, "UserSecrets"), keys, screen, TimeProvider.System, environment: file);
    }

    [TearDown]
    public void TearDown()
    {
        service.Dispose();
        TestDirectory.Delete(root);
    }

    void Seal(SealedEnvironment environment) =>
        File.WriteAllText(Path.Combine(root, "environment.json"), UserSecretsVault.Seal(EnvironmentFile.Id, 1, environment.ToDocument(), [Hello]));

    static readonly SealedEnvironment Marked = SealedEnvironment.Empty
        .WithGlobal([new("Payments__ApiKey", "test-value"), new("OTHER", "x")]).WithConfiguration("Payments__ApiKey");

    Task<AgentReply> Load(string? folder = null, params string[] present) =>
        service.HandleAsync(AgentRequest.ForEnvironment(folder ?? app, present), Exe, CancellationToken.None);

    static Dictionary<string, string> Values(AgentReply reply) => JsonSerializer.Deserialize<Dictionary<string, string>>(reply.Json!)!;

    [Test]
    public async Task Nothing_sealed_answers_none_without_a_prompt()
    {
        var reply = await Load();
        Assert.That((reply.Status, reply.Json), Is.EqualTo((AgentStatus.Ok, "{}")));
        Assert.That(screen.Shown, Is.Empty);
    }

    [Test]
    public async Task Nothing_marked_asks_nothing()
    {
        Seal(SealedEnvironment.Empty.WithGlobal([new("OTHER", "x")]));
        Assert.That(Values(await Load()), Is.Empty);
        Assert.That(screen.Shown, Is.Empty);
    }

    [Test]
    public async Task Allowed_for_the_session_hands_over_only_the_marked_variables_and_does_not_ask_again()
    {
        Seal(Marked);
        screen.Answers.Enqueue(ConsentAnswer.AllowForSession);
        var first = await Load();
        Assert.That(Values(first), Is.EqualTo(new Dictionary<string, string> { ["Payments__ApiKey"] = "test-value" }));
        Assert.That(screen.Shown.Single().Folder, Is.EqualTo(app));
        Assert.That(screen.Shown.Single().IsEnvironment, Is.True);
        Assert.That(Values(await Load()), Has.Count.EqualTo(1));
        Assert.That(screen.Shown, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task A_folder_override_is_a_new_question()
    {
        Seal(Marked.WithFolder(app, [new("Payments__ApiKey", "folder-value")]));
        screen.Answers.Enqueue(ConsentAnswer.AllowForSession);
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);
        await Load(root);
        Assert.That(Values(await Load(app))["Payments__ApiKey"], Is.EqualTo("folder-value"));
        Assert.That(screen.Shown, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task A_no_is_denied()
    {
        Seal(Marked);
        screen.Answers.Enqueue(ConsentAnswer.Deny);
        Assert.That((await Load()).Status, Is.EqualTo(AgentStatus.Denied));
    }

    [Test]
    public async Task A_variable_the_process_has_is_neither_asked_about_nor_sent()
    {
        Seal(Marked);
        Assert.That(Values(await Load(null, "PAYMENTS__APIKEY")), Is.Empty);
        Assert.That(screen.Shown, Is.Empty);
    }

    [Test]
    public async Task Locked_offers_to_unlock_and_a_decline_is_a_refusal()
    {
        Seal(Marked);
        keys.IsUnlocked = false;
        Assert.That((await Load()).Status, Is.EqualTo(AgentStatus.Denied));
        Assert.That(screen.UnlockAsked, Is.EqualTo(1));
    }

    [Test]
    public async Task A_relative_folder_is_an_error() =>
        Assert.That((await Load("shop")).Status, Is.EqualTo(AgentStatus.Error));
}

[NonParallelizable]
public class SealedEnvironmentProviderTests
{
    const string Name = "TIRESIAS_TEST__SEALED";
    StringWriter notices = null!;

    sealed class FakeAgent(AgentReply? reply) : IUserSecretsAgent
    {
        public List<AgentRequest> Requests { get; } = [];

        public AgentReply? TryLoad(AgentRequest request, TimeSpan wait)
        {
            Requests.Add(request);
            return reply;
        }
    }

    [SetUp]
    public void SetUp()
    {
        SealedEnvironmentProvider.Reset();
        notices = new StringWriter();
        SealedEnvironmentProvider.Notices = notices;
        SealedEnvironmentProvider.Folder = () => OperatingSystem.IsWindows() ? @"C:\src\shop" : "/src/shop";
        Environment.SetEnvironmentVariable(Name, null);
    }

    [TearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable(Name, null);
        SealedEnvironmentProvider.Notices = Console.Error;
        SealedEnvironmentProvider.Folder = () => Environment.CurrentDirectory;
        SealedEnvironmentProvider.Reset();
        notices.Dispose();
    }

    static AgentReply Given(string value) => new(AgentStatus.Ok, JsonSerializer.Serialize(new Dictionary<string, string> { [Name] = value }));

    [Test]
    public void A_given_variable_reaches_configuration_through_the_environment_source_at_its_precedence()
    {
        var agent = new FakeAgent(Given("from-tiresias"));
        var manager = new ConfigurationManager();
        manager.AddInMemoryCollection(new Dictionary<string, string?> { ["TIRESIAS_TEST:SEALED"] = "from-appsettings" });
        manager.AddEnvironmentVariables();
        manager.AddInMemoryCollection(new Dictionary<string, string?> { ["Other"] = "x" });
        manager.AddSealedEnvironment(agent);

        Assert.That(manager["TIRESIAS_TEST:SEALED"], Is.EqualTo("from-tiresias"));
        // ConfigurationManager starts with a memory source of its own, for values set on it.
        var sources = ((IConfigurationBuilder)manager).Sources.Skip(1).Select(s => s.GetType().Name).ToArray();
        Assert.That(sources, Is.EqualTo(new[] { "MemoryConfigurationSource", "SealedEnvironmentSource", "EnvironmentVariablesConfigurationSource", "MemoryConfigurationSource" }));
        Assert.That(agent.Requests.Single().Op, Is.EqualTo(AgentRequest.LoadEnvironment));
        Assert.That(notices.ToString(), Does.Contain(Name).And.Not.Contain("from-tiresias"));
    }

    [Test]
    public void A_builder_that_reads_no_environment_gets_nothing()
    {
        var agent = new FakeAgent(Given("from-tiresias"));
        var builder = new ConfigurationBuilder().AddEnvironmentVariables("SOME_PREFIX_").AddSealedEnvironment(agent);
        Assert.That(builder.Sources.OfType<SealedEnvironmentSource>(), Is.Empty);
        builder.Build();
        Assert.That(agent.Requests, Is.Empty);
    }

    [Test]
    public void Asks_once_per_process_however_often_the_host_rebuilds()
    {
        var agent = new FakeAgent(new(AgentStatus.Denied, Message: "declined"));
        var builder = new ConfigurationBuilder().AddEnvironmentVariables().AddSealedEnvironment(agent).AddSealedEnvironment(agent);
        builder.Build();
        builder.Build();
        Assert.That(agent.Requests, Has.Count.EqualTo(1));
        Assert.That(builder.Sources.OfType<SealedEnvironmentSource>().Count(), Is.EqualTo(1));
        Assert.That(notices.ToString(), Does.Contain("declined"));
    }

    [Test]
    public void Without_the_app_the_app_starts_quietly_without_them()
    {
        var root = new ConfigurationBuilder().AddEnvironmentVariables().AddSealedEnvironment(new FakeAgent(null)).Build();
        Assert.That(root["TIRESIAS_TEST:SEALED"], Is.Null);
        Assert.That(notices.ToString(), Is.Empty);
    }

    [Test]
    public void Sends_the_names_the_process_already_has()
    {
        Environment.SetEnvironmentVariable(Name, "already");
        var agent = new FakeAgent(new(AgentStatus.Ok, "{}"));
        new ConfigurationBuilder().AddEnvironmentVariables().AddSealedEnvironment(agent).Build();
        Assert.That(agent.Requests.Single().Present, Does.Contain(Name));
    }
}
