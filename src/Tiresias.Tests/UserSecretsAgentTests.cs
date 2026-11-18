using System.IO.Pipes;
using System.Text.Json.Nodes;
using NSec.Cryptography;
using Tiresias.Audit;
using Tiresias.Extensions.Configuration;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class UserSecretsPolicyTests
{
    [TestCase(SecretsFileKind.None, false, false, false, UserSecretsAction.ServeAsIs)]
    [TestCase(SecretsFileKind.Invalid, true, true, false, UserSecretsAction.Error)]
    [TestCase(SecretsFileKind.Plain, false, true, false, UserSecretsAction.ServeAsIs)]
    [TestCase(SecretsFileKind.Plain, true, false, false, UserSecretsAction.ServeAsIs)]
    [TestCase(SecretsFileKind.Plain, true, true, false, UserSecretsAction.SealAndServe)]
    [TestCase(SecretsFileKind.Sealed, false, true, true, UserSecretsAction.Deny)]
    [TestCase(SecretsFileKind.Sealed, true, true, false, UserSecretsAction.AskConsent)]
    [TestCase(SecretsFileKind.Sealed, true, true, true, UserSecretsAction.Serve)]
    public void Decides(SecretsFileKind kind, bool unlocked, bool recovery, bool remembered, UserSecretsAction expected) =>
        Assert.That(UserSecretsPolicy.Decide(kind, hasPlainAdditions: false, unlocked, recovery, remembered).Action, Is.EqualTo(expected));

    [Test]
    public void Plain_keys_beside_the_envelope_are_resealed_only_with_a_recovery_key()
    {
        Assert.That(UserSecretsPolicy.Decide(SecretsFileKind.Sealed, true, true, true, false).Reseal, Is.True);
        Assert.That(UserSecretsPolicy.Decide(SecretsFileKind.Sealed, true, true, false, false).Reseal, Is.False);
    }

    [Test]
    public void Locked_never_opens_a_sealed_file_even_when_remembered()
    {
        var plan = UserSecretsPolicy.Decide(SecretsFileKind.Sealed, false, unlocked: false, true, remembered: true);
        Assert.That(plan.Action, Is.EqualTo(UserSecretsAction.Deny));
        Assert.That(plan.Message, Does.Contain("Unlock"));
    }

    [Test]
    public void A_request_must_name_the_folder_its_id_lives_in()
    {
        var root = Path.Combine(Path.GetTempPath(), "UserSecrets");
        Assert.That(UserSecretsPolicy.Validate(new(AgentRequest.LoadUserSecrets, "abc", Path.Combine(root, "abc")), root), Is.Null);
        Assert.That(UserSecretsPolicy.Validate(new(AgentRequest.LoadUserSecrets, "abc", Path.Combine(root, "other")), root), Is.Not.Null);
        Assert.That(UserSecretsPolicy.Validate(new(AgentRequest.LoadUserSecrets, "..", root), root), Is.Not.Null);
        Assert.That(UserSecretsPolicy.Validate(new(AgentRequest.LoadUserSecrets, "abc", Path.GetTempPath()), root), Is.Not.Null);
        Assert.That(UserSecretsPolicy.Validate(new("other.op", "abc", Path.Combine(root, "abc")), root), Is.Not.Null);
    }
}

public class ConsentMemoryTests
{
    static readonly DateTimeOffset Now = new(2026, 1, 5, 9, 0, 0, TimeSpan.Zero);

    [Test]
    public void Remembers_until_the_expiry()
    {
        var memory = new ConsentMemory();
        memory.Remember(@"C:\apps\web.exe", "id", Now.AddHours(1));
        Assert.That(memory.IsAllowed(@"C:\apps\web.exe", "id", Now.AddMinutes(59)), Is.True);
        Assert.That(memory.IsAllowed(@"C:\apps\web.exe", "id", Now.AddHours(1)), Is.False);
    }

    [Test]
    public void Is_per_program_and_per_secrets_id()
    {
        var memory = new ConsentMemory();
        memory.Remember(@"C:\apps\web.exe", "id", Now.AddHours(1));
        Assert.That(memory.IsAllowed(@"C:\apps\other.exe", "id", Now), Is.False);
        Assert.That(memory.IsAllowed(@"C:\apps\web.exe", "other", Now), Is.False);
    }

    [Test]
    public void An_unidentified_program_is_never_remembered()
    {
        var memory = new ConsentMemory();
        memory.Remember(null, "id", Now.AddHours(1));
        Assert.That(memory.IsAllowed(null, "id", Now), Is.False);
    }

    [Test]
    public void Clear_forgets_everything()
    {
        var memory = new ConsentMemory();
        memory.Remember(@"C:\apps\web.exe", "id", Now.AddHours(1));
        memory.Clear();
        Assert.That(memory.IsAllowed(@"C:\apps\web.exe", "id", Now), Is.False);
    }

    [Test]
    public void The_consent_lines_name_keys_and_never_values()
    {
        var lines = new UserSecretsConsentRequest(@"C:\apps\web.exe", "id", ["Db:Password", "ApiKey"]).Describe();
        Assert.That(string.Join("\n", lines), Does.Contain("Db:Password").And.Contain(@"C:\apps\web.exe").And.Contain("Keys (2)"));
    }
}

public class UserSecretsEditTests
{
    [Test]
    public void Set_stores_the_key_flat_and_drops_a_nested_copy()
    {
        var doc = new JsonObject { ["Db"] = new JsonObject { ["Password"] = "old", ["User"] = "u" } };
        UserSecretsEdit.Set(doc, "Db:Password", "new");
        Assert.That(UserSecretsEdit.Flatten(doc), Is.EquivalentTo(new Dictionary<string, string> { ["Db:User"] = "u", ["Db:Password"] = "new" }));
    }

    [Test]
    public void Remove_finds_a_nested_key_case_insensitively_and_prunes_empty_parents()
    {
        var doc = new JsonObject { ["Db"] = new JsonObject { ["Password"] = "p" }, ["A"] = "1" };
        Assert.That(UserSecretsEdit.Remove(doc, "db:password"), Is.True);
        Assert.That(doc.ContainsKey("Db"), Is.False);
        Assert.That(UserSecretsEdit.Remove(doc, "Missing"), Is.False);
    }

    [Test]
    public void Flatten_reads_numbers_and_arrays_as_configuration_does()
    {
        var doc = JsonNode.Parse("""{ "Port": 5432, "Hosts": ["a", "b"], "On": true }""")!.AsObject();
        Assert.That(UserSecretsEdit.Flatten(doc), Is.EqualTo(new KeyValuePair<string, string>[]
        {
            new("Port", "5432"), new("Hosts:0", "a"), new("Hosts:1", "b"), new("On", "true"),
        }));
    }

    [Test]
    public void Apply_removes_sets_and_leaves_untouched_keys_where_they_were()
    {
        var doc = new JsonObject { ["Db"] = new JsonObject { ["Password"] = "p", ["User"] = "u" }, ["Gone"] = "x" };
        var changed = UserSecretsEdit.Apply(doc, [new("Db:Password", "p"), new("Db:User", "v"), new("New", "n")]);

        Assert.That(changed, Is.EqualTo(3));
        Assert.That((string?)doc["Db"]!["Password"], Is.EqualTo("p"), "untouched keys keep their nesting");
        Assert.That((string?)doc["Db:User"], Is.EqualTo("v"));
        Assert.That(doc.ContainsKey("Gone"), Is.False);
    }

    [Test]
    public void Apply_refuses_an_empty_or_duplicate_key()
    {
        Assert.Throws<ArgumentException>(() => UserSecretsEdit.Apply(new JsonObject(), [new(" ", "v")]));
        Assert.Throws<ArgumentException>(() => UserSecretsEdit.Apply(new JsonObject(), [new("A", "1"), new("a", "2")]));
    }
}

/// <summary>The agent's side end to end: real files, a stand-in Hello key, a scripted consent screen.</summary>
public class UserSecretsServiceTests
{
    const string Id = "svc-test-id";
    const string Exe = @"C:\apps\web.exe";

    string root = "";
    string folder = "";
    Keys keys = null!;
    Screen screen = null!;
    ManualTime time = null!;
    UserSecretsService service = null!;

    sealed class Keys : IUserSecretsKeys
    {
        public static readonly X25519KeyWrapper Hello = X25519KeyWrapper.ForKey("hello", Key.Create(KeyAgreementAlgorithm.X25519));
        public static readonly X25519KeyWrapper RecoveryKey = X25519KeyWrapper.ForKey("recovery", Key.Create(KeyAgreementAlgorithm.X25519));
        public bool IsUnlocked { get; set; } = true;
        public bool HasRecovery { get; set; } = true;
        public IKeyWrapper? Unlocked => IsUnlocked ? Hello : null;
        public IKeyWrapper? Recovery => HasRecovery ? RecoveryKey : null;
    }

    sealed class Screen : IUserSecretsConsentPrompt
    {
        public Queue<ConsentAnswer> Answers { get; } = new();
        public List<UserSecretsConsentRequest> Shown { get; } = [];
        public TaskCompletionSource? Hold { get; set; }

        /// <summary>The screen went away unanswered (the session locked), as the app reports it.</summary>
        public bool Vanish { get; set; }

        /// <summary>Set to unlock when asked; <c>null</c> keeps the interface's default (decline).</summary>
        public Keys? UnlockWith { get; set; }
        public int UnlockAsked { get; private set; }

        public Task<bool> AskUnlockAsync(string? executable, string userSecretsId, CancellationToken ct)
        {
            UnlockAsked++;
            if (UnlockWith is null)
                return Task.FromResult(false);
            UnlockWith.IsUnlocked = true;
            return Task.FromResult(true);
        }

        public async Task<ConsentAnswer> AskAsync(UserSecretsConsentRequest request, CancellationToken ct)
        {
            Shown.Add(request);
            if (Vanish)
                throw new OperationCanceledException();
            if (Hold is { } hold)
                await hold.Task.WaitAsync(ct);
            return Answers.Dequeue();
        }
    }

    [SetUp]
    public void SetUp()
    {
        root = Directory.CreateTempSubdirectory("tir-us-").FullName;
        folder = Path.Combine(root, Id);
        Directory.CreateDirectory(folder);
        keys = new Keys();
        screen = new Screen();
        time = new ManualTime(new DateTimeOffset(2026, 1, 5, 9, 0, 0, TimeSpan.Zero));
        service = new UserSecretsService(root, keys, screen, time);
    }

    [TearDown]
    public void TearDown()
    {
        service.Dispose();
        TestDirectory.Delete(root);
    }

    string FilePath => Path.Combine(folder, SecretsFile.FileName);

    Task<AgentReply> Load(string? caller = Exe) => service.HandleAsync(new(AgentRequest.LoadUserSecrets, Id, folder), caller, CancellationToken.None);

    [Test]
    public async Task First_load_seals_the_plaintext_file_without_a_prompt()
    {
        File.WriteAllText(FilePath, """{ "Db": { "Password": "hunter2" } }""");

        var reply = await Load();

        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Ok));
        Assert.That(reply.Json, Does.Contain("hunter2"));
        Assert.That(screen.Shown, Is.Empty);
        var onDisk = File.ReadAllText(FilePath);
        Assert.That(SecretsFile.Classify(onDisk), Is.EqualTo(SecretsFileKind.Sealed));
        Assert.That(onDisk, Does.Not.Contain("hunter2").And.Not.Contain("Password"));
    }

    [Test]
    public async Task Only_the_first_seal_is_announced()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        var announced = new List<string>();
        service.FirstSealed += announced.Add;
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);

        await Load();
        await Load();

        Assert.That(announced, Is.EqualTo(new[] { Id }));
    }

    [Test]
    public async Task Afterwards_the_consent_screen_shows_keys_and_the_program_and_allow_once_asks_again()
    {
        File.WriteAllText(FilePath, """{ "Db": { "Password": "hunter2" } }""");
        await Load();
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);

        var first = await Load();
        await Load();

        Assert.That(first.Json, Does.Contain("hunter2"));
        Assert.That(screen.Shown, Has.Count.EqualTo(2));
        Assert.That(screen.Shown[0].Executable, Is.EqualTo(Exe));
        Assert.That(screen.Shown[0].Keys, Is.EqualTo(new[] { "Db:Password" }));
    }

    [Test]
    public async Task Allow_for_this_session_is_remembered_until_lock()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        screen.Answers.Enqueue(ConsentAnswer.AllowForSession);
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);

        await Load();
        await Load();
        Assert.That(screen.Shown, Has.Count.EqualTo(1));

        service.Lock();
        await Load();
        Assert.That(screen.Shown, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task Allow_for_this_session_expires()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        screen.Answers.Enqueue(ConsentAnswer.AllowForSession);
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);
        await Load();

        time.Now += UserSecretsService.SessionLength;
        await Load();
        Assert.That(screen.Shown, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task Deny_returns_denied_and_no_document()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        screen.Answers.Enqueue(ConsentAnswer.Deny);

        var reply = await Load();

        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Denied));
        Assert.That(reply.Json, Is.Null);
    }

    [Test]
    public async Task Locked_denies_a_sealed_file_without_a_prompt()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        keys.IsUnlocked = false;

        var reply = await Load();

        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Denied));
        Assert.That(reply.Message, Does.Contain("locked"));
        Assert.That(screen.Shown, Is.Empty);
    }

    [Test]
    public async Task A_screen_closed_by_a_lock_is_not_reported_as_declined()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        screen.Vanish = true;

        var reply = await Load();

        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Denied));
        Assert.That(reply.Message, Does.Not.Contain("declined"));
        Assert.That(reply.Message, Does.Contain("locked"));
    }

    [Test]
    public async Task Locked_offers_to_unlock_then_asks_consent()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        keys.IsUnlocked = false;
        screen.UnlockWith = keys;
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);

        var reply = await Load();

        Assert.That(screen.UnlockAsked, Is.EqualTo(1));
        Assert.That(screen.Shown, Has.Count.EqualTo(1));
        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Ok));
        Assert.That(reply.Json, Does.Contain("\"A\""));
    }

    [Test]
    public async Task Locked_does_not_offer_to_unlock_for_a_plaintext_file()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        keys.IsUnlocked = false;
        screen.UnlockWith = keys;

        await Load();

        Assert.That(screen.UnlockAsked, Is.Zero);
    }

    [Test]
    public async Task Locked_serves_a_plaintext_file_unchanged()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        keys.IsUnlocked = false;

        var reply = await Load();

        Assert.That(reply.Json, Does.Contain("\"A\""));
        Assert.That(SecretsFile.Classify(File.ReadAllText(FilePath)), Is.EqualTo(SecretsFileKind.Plain));
    }

    [Test]
    public async Task Without_a_recovery_key_a_plaintext_file_is_not_sealed()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        keys.HasRecovery = false;
        await Load();
        Assert.That(SecretsFile.Classify(File.ReadAllText(FilePath)), Is.EqualTo(SecretsFileKind.Plain));
    }

    [Test]
    public async Task Plain_keys_added_beside_the_envelope_are_sealed_after_consent()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        var file = JsonNode.Parse(File.ReadAllText(FilePath))!.AsObject();
        file["B"] = "added-in-clear";
        File.WriteAllText(FilePath, file.ToJsonString());
        screen.Answers.Enqueue(ConsentAnswer.AllowOnce);

        var reply = await Load();

        Assert.That(reply.Json, Does.Contain("added-in-clear"));
        Assert.That(File.ReadAllText(FilePath), Does.Not.Contain("added-in-clear"));
    }

    [Test]
    public async Task Locking_while_the_screen_is_open_refuses_the_request()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        screen.Hold = new TaskCompletionSource();

        var pending = Load();
        while (screen.Shown.Count == 0)
            await Task.Delay(5);
        service.Lock();
        var reply = await pending;

        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Denied));
        Assert.That(reply.Message, Does.Contain("locked"));
    }

    [Test]
    public async Task A_second_request_waits_for_the_open_screen_and_uses_its_session_answer()
    {
        File.WriteAllText(FilePath, """{ "A": "1" }""");
        await Load();
        screen.Hold = new TaskCompletionSource();
        screen.Answers.Enqueue(ConsentAnswer.AllowForSession);

        var first = Load();
        while (screen.Shown.Count == 0)
            await Task.Delay(5);
        var second = Load();
        screen.Hold.SetResult();

        Assert.That((await first).Status, Is.EqualTo(AgentStatus.Ok));
        Assert.That((await second).Status, Is.EqualTo(AgentStatus.Ok));
        Assert.That(screen.Shown, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task A_folder_that_is_not_the_ids_own_is_refused()
    {
        var reply = await service.HandleAsync(new(AgentRequest.LoadUserSecrets, Id, root), Exe, CancellationToken.None);
        Assert.That(reply.Status, Is.EqualTo(AgentStatus.Error));
    }

    [Test]
    public async Task Decisions_are_audited_with_keys_counted_and_no_values()
    {
        var auditPath = Path.Combine(root, "activity.jsonl");
        using var audit = new AuditLog(auditPath, time);
        using var audited = new UserSecretsService(root, keys, screen, time, audit);
        File.WriteAllText(FilePath, """{ "Db": { "Password": "hunter2" } }""");

        await audited.HandleAsync(new(AgentRequest.LoadUserSecrets, Id, folder), Exe, CancellationToken.None);

        var log = File.ReadAllText(auditPath);
        Assert.That(log, Does.Contain("usersecrets/" + Id).And.Contain("web.exe").And.Not.Contain("hunter2"));
    }
}

/// <summary>The real configuration provider talking to the real pipe server.</summary>
public class AgentPipeTests
{
    [Test]
    public async Task The_configuration_client_gets_its_secrets_through_the_pipe()
    {
        var pipe = $"tiresias-test-{Guid.NewGuid():N}";
        using var stop = new CancellationTokenSource();
        string? seenCaller = "unset";
        var server = new AgentPipeServer<AgentRequest, AgentReply>(pipe,
            (request, caller, _) =>
            {
                seenCaller = caller;
                return Task.FromResult(new AgentReply(AgentStatus.Ok, $$"""{ "Id": "{{request.UserSecretsId}}" }"""));
            },
            _ => "test-caller");
        var serving = server.RunAsync(stop.Token);

        var reply = await Task.Run(() => new NamedPipeUserSecretsAgent(pipe).TryLoad(new(AgentRequest.LoadUserSecrets, "abc", "dir")));

        Assert.That(reply!.Status, Is.EqualTo(AgentStatus.Ok));
        Assert.That(reply.Json, Does.Contain("abc"));
        Assert.That(seenCaller, Is.EqualTo("test-caller"));
        await stop.CancelAsync();
        await serving;
    }

    [Test]
    public void Without_a_server_the_client_reports_no_agent() =>
        Assert.That(new NamedPipeUserSecretsAgent($"tiresias-test-{Guid.NewGuid():N}").TryLoad(new(AgentRequest.LoadUserSecrets, "abc", "dir")), Is.Null);
}
