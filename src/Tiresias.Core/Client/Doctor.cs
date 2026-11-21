using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.Client;

public enum DoctorStatus
{
    Ok,
    Warn,
    Fail,
}

/// <summary>
/// One line of <c>tir doctor</c>. A line with a fix, or about how a credential is delivered, is a
/// <b>finding</b>: something the user can act on. A delivery finding also says where it sits on the
/// two axes now and where its fix takes it.
/// </summary>
/// <param name="Fix">What raises it, for a UI to open filled in or the CLI to print.</param>
/// <param name="Now">The delivery's position today; <c>null</c> on a line about Tiresias's own health.</param>
/// <param name="Better">The position <paramref name="Fix"/> reaches.</param>
/// <param name="Kind">For a finding a check can raise many times, what its findings are, as a plural noun phrase
/// ("projects that ..."), so a UI can show them as one line with a count. <c>null</c> for a one-off line.</param>
/// <param name="Subject">What the finding is about that can change under the same name, such as a file's key
/// names. A dismissal is bound to it, so a change raises the finding again. Never a secret value.</param>
public sealed record DoctorCheck(string Name, DoctorStatus Status, string Detail, DoctorFix? Fix = null, Position? Now = null, Position? Better = null, string? Kind = null, string? Subject = null)
{
    public bool IsFinding => Fix is not null || Now is not null;
}

/// <summary>What the vault file says about recoverability: which secrets lack a Hello or a recovery wrap.</summary>
/// <param name="Unbound">Secrets not yet bound to their policy, which the broker refuses until migrated.</param>
public sealed record DoctorVault(int Secrets, IReadOnlyList<string> WithoutHello, IReadOnlyList<string> WithoutRecovery, IReadOnlyList<string>? Unbound = null);

/// <summary>A file the doctor read: its path and text (<c>null</c> when unreadable).</summary>
public sealed record DoctorFile(string Path, string? Text);

/// <summary>
/// The facts <c>tir doctor</c> judges, gathered by the Keyring from the machine. Every member only
/// observes; nothing here changes state, prompts, or reads a secret value.
/// </summary>
public interface IDoctorProbe
{
    bool Enrolled { get; }
    bool HasDeviceKey { get; }
    bool RecoveryKeySet { get; }

    /// <summary>Enrolled with the broker this device hosts itself (solo mode) rather than a remote one.</summary>
    bool Solo => false;

    /// <summary><c>null</c> when the vault file is missing.</summary>
    DoctorVault? Vault { get; }

    /// <summary>The HTTP status of an unsigned call to the broker (401 means up), or <c>null</c> when unreachable.</summary>
    Task<int?> BrokerStatusAsync();

    /// <summary>Whether something answers on the forwarder's loopback port.</summary>
    Task<bool> ForwarderListeningAsync();

    /// <summary>Every <c>secrets.json</c> under the user-secrets root.</summary>
    IEnumerable<DoctorFile> UserSecretsFiles();

    /// <summary>Project files to check for unprotected user secrets; empty unless asked for.</summary>
    IEnumerable<DoctorFile> Projects();

    /// <summary>Names of user environment variables that look like secrets and aren't sealed. Never values.</summary>
    IReadOnlyList<string> ExposedVariables => [];

    /// <summary><c>appsettings*.json</c> files to check for passwords and certificate paths; empty unless asked for.</summary>
    IEnumerable<DoctorFile> ConfigFiles() => [];

    /// <summary>Paths of files holding a private key (<c>.pfx</c>, <c>.p12</c>, or a PEM with one); empty unless asked for. Never their contents.</summary>
    IEnumerable<string> KeyFiles() => [];

    /// <summary>The <c>.git/config</c> of every repository in the project folders; empty unless asked for.</summary>
    IEnumerable<DoctorFile> GitConfigs() => [];

    /// <summary>The user's git credential helper and stored hosts; <c>null</c> when unknown. Never a token.</summary>
    DoctorGitCredentials? GitCredentials => null;

    /// <summary>The package tools' credential files, the user's own and those in the project folders; see <see cref="Doctor.PublishingKeys"/>.</summary>
    IEnumerable<DoctorToolFile> ToolFiles() => [];

    /// <summary>Names of the user's Windows environment variables, whatever they hold. Never values.</summary>
    IReadOnlyCollection<string> UserVariableNames => [];

    /// <summary>The vault's RavenDB services with their certificates as recorded at setup. Never the certificate.</summary>
    IEnumerable<DoctorRavenCertificate> RavenCertificates() => [];

    /// <summary>The sealed environment's deliveries, by name; <c>null</c> while locked. See <see cref="Doctor.KeysAsValues"/>.</summary>
    DoctorEnvironment? SealedEnvironment => null;

    /// <summary>Extensions installed for the user in programs that host them, from their metadata.</summary>
    IEnumerable<InstalledExtension> Extensions() => [];

    /// <summary>Programs Windows starts at log-on, with whether each is signed.</summary>
    IEnumerable<StartupEntry> StartupEntries() => [];

    /// <summary>Which program got which credential, and when, from the local activity and audit logs.</summary>
    IEnumerable<CredentialUse> CredentialUses() => [];

    /// <summary>Paths of blocked programs whose file still exists.</summary>
    IEnumerable<string> BlockedPrograms() => [];

    /// <summary>When the user last started each program themselves, where Windows records it (UserAssist).</summary>
    IEnumerable<ProgramRun> ProgramRuns() => [];

    /// <summary>The uninstall registry entries, machine and user, each with whether its uninstaller and folder are on disk.</summary>
    IEnumerable<UninstallEntry> UninstallEntries() => [];

    /// <summary>The config files of the CLIs that sign in as the user. See <see cref="Doctor.CliSignIns"/>.</summary>
    DoctorCliConfigs CliConfigs => new(null, null);

    /// <summary>The slug of a vault GitHub App service, for <c>tir exec gh</c>; <c>null</c> when there is none.</summary>
    string? GitHubAppService => null;
}

/// <summary>
/// The <c>tir doctor</c> checklist: turns probe facts into ok / warn / fail lines. A failure is
/// something that leaks or can't be recovered; a warning is something that works but shouldn't.
/// Of an unprotected secrets file it reports how many keys it holds, never their names or values.
/// </summary>
public static partial class Doctor
{
    public static async Task<IReadOnlyList<DoctorCheck>> RunAsync(IDoctorProbe probe)
    {
        var checks = new List<DoctorCheck>
        {
            probe.Enrolled ? new("broker pinned", DoctorStatus.Ok, "enrolled") : new("broker pinned", DoctorStatus.Fail, "not enrolled: run tir enroll"),
            probe.HasDeviceKey ? new("device key", DoctorStatus.Ok, "present") : new("device key", DoctorStatus.Fail, "missing: run tir enroll"),
            probe.RecoveryKeySet ? new("recovery key", DoctorStatus.Ok, "set") : new("recovery key", DoctorStatus.Fail, "not set: secrets depend on this TPM alone; run tir recovery init"),
            Vault(probe.Vault),
        };

        if (probe.Solo)
            checks.AddRange(SoloTradeOffs);
        if (probe.Enrolled)
            checks.Add(await probe.BrokerStatusAsync() switch
            {
                null when probe.Solo => new("broker reachable", DoctorStatus.Fail, "no answer: the broker runs inside the Tiresias app; start the app (or tir agent)"),
                null => new("broker reachable", DoctorStatus.Fail, "no answer (NetBird down, or the broker stopped)"),
                401 => new("broker reachable", DoctorStatus.Ok, "answers and refuses unsigned calls"),
                var status => new("broker reachable", DoctorStatus.Warn, $"answered {status} to an unsigned call; expected 401"),
            });
        if (probe.Solo)
            checks.Add(new("forwarder", DoctorStatus.Ok, "not needed: the solo broker identifies callers itself"));
        else
            checks.Add(await probe.ForwarderListeningAsync()
                ? new("forwarder", DoctorStatus.Ok, "listening on loopback")
                : new("forwarder", DoctorStatus.Warn, "not running: placeholders work only against the broker directly"));

        checks.AddRange(probe.UserSecretsFiles().Select(UserSecretsFile).OfType<DoctorCheck>());
        checks.AddRange(probe.Projects().Select(Project).OfType<DoctorCheck>());
        checks.Add(probe.ExposedVariables switch
        {
            [] => new(VariablesCheck, DoctorStatus.Ok, "none of your user environment variables look like secrets"),
            var names => new(VariablesCheck, DoctorStatus.Warn,
                $"{names.Count} look like secrets and every program you run can read them: {string.Join(", ", names)}. Seal them in the app's Environment variables window, or with tir env protect",
                new ProtectVariables(names), Position.Plaintext, Position.SealedApproved),
        });
        checks.AddRange(ConfigChecks(probe.UserSecretsFiles(), probe.ConfigFiles(), probe.KeyFiles()));
        checks.AddRange(GitTokens(probe.GitConfigs(), probe.GitCredentials));
        checks.AddRange(PublishingKeys(probe.ToolFiles(), probe.UserVariableNames));
        checks.AddRange(RavenExpiry(probe.RavenCertificates(), DateTimeOffset.UtcNow));
        checks.AddRange(KeysAsValues(probe.SealedEnvironment));
        checks.AddRange(CliSignIns(probe.CliConfigs, probe.GitHubAppService));
        var (uses, runs, installed, now) = (probe.CredentialUses().ToArray(), probe.ProgramRuns().ToArray(), probe.UninstallEntries().ToArray(), DateTimeOffset.UtcNow);
        checks.AddRange(AttackSurface(probe.Extensions(), probe.StartupEntries(), uses, probe.BlockedPrograms(), now, runs));
        checks.AddRange(UninstallEntries(installed));
        checks.AddRange(UnusedApplications(installed, runs, uses, now));
        return checks;
    }

    /// <summary>The name of the environment variables check.</summary>
    public const string VariablesCheck = "environment variables";

    /// <summary>What solo mode gives up next to a remote broker (docs/desktop-app.md), stated on every run.</summary>
    static readonly DoctorCheck[] SoloTradeOffs =
    [
        new("mode", DoctorStatus.Ok, "Solo: the broker runs on this device; encryption, leases, placeholders, consent and audit all apply"),
        new("egress", DoctorStatus.Warn, "Solo: requests leave from your own connection, so there is no fixed IP for upstreams to allow-list"),
        new("isolation", DoctorStatus.Warn, "Solo: secrets live on the same machine as your agents and are not protected from code running as admin"),
        new("broker process", DoctorStatus.Warn, "Broker runs inside the app: install the service for process isolation (not built yet)"),
    ];

    static DoctorCheck Vault(DoctorVault? vault)
    {
        const string name = "vault";
        if (vault is null)
            return new(name, DoctorStatus.Warn, "no vault file yet");
        if (vault.WithoutRecovery.Count > 0)
            return new(name, DoctorStatus.Fail, $"{vault.WithoutRecovery.Count} of {vault.Secrets} secrets have no recovery wrap: {string.Join(", ", vault.WithoutRecovery)}");
        if (vault.WithoutHello.Count > 0)
            return new(name, DoctorStatus.Warn, $"{vault.WithoutHello.Count} of {vault.Secrets} secrets can't be unlocked with Hello: {string.Join(", ", vault.WithoutHello)}");
        if (vault.Unbound is { Count: > 0 } unbound)
            return new(name, DoctorStatus.Fail, $"{unbound.Count} of {vault.Secrets} secrets aren't bound to their services' settings yet, so the broker refuses them: "
                + $"{string.Join(", ", unbound)}. Unlock in the Tiresias app and approve, or run tir vault migrate");
        return new(name, DoctorStatus.Ok, $"{vault.Secrets} secrets, all with Hello and recovery wraps, bound to their services' settings");
    }

    /// <returns><c>null</c> for an empty file, one without keys, or one that is sealed and clean: nothing to report.</returns>
    /// <remarks>
    /// A plaintext file is a warning, not a failure: it is what .NET does by default, the app works,
    /// and sealing it breaks any app that doesn't use Tiresias.Extensions.Configuration yet. A file of
    /// settings only (<see cref="SecretsContents"/>) has nothing to seal, so it is an Ok line.
    /// </remarks>
    static DoctorCheck? UserSecretsFile(DoctorFile file)
    {
        var id = UserSecretsIdOf(file.Path);
        var name = $"user secrets {id}";
        switch (SecretsFile.Classify(file.Text))
        {
            case SecretsFileKind.Plain:
                var document = Parse(file.Text!);
                var keys = UserSecretsVault.FlattenKeys(document);
                return SecretsContents.Of(document) switch
                {
                    SecretsContent.Empty => null,
                    SecretsContent.Settings => new(name, DoctorStatus.Ok, $"holds settings, not secrets: {Keys(keys.Count)}"),
                    _ => new(name, DoctorStatus.Warn, $"in plain text: {Keys(keys.Count)} any program running as you can read. Seal it once the project uses Tiresias.Extensions.Configuration: run the app once, or use Seal now in the secrets editor",
                        new ReviewUserSecrets(id), Position.Plaintext, Position.SealedApproved, "user secrets files in plain text", KeyNames(keys)),
                };
            case SecretsFileKind.Invalid:
                return new(name, DoctorStatus.Fail, "not valid JSON; apps reading it will fail at startup", new ReviewUserSecrets(id), Kind: "user secrets files that aren't valid JSON");
            case SecretsFileKind.Sealed:
                JsonObject? plain;
                try
                {
                    plain = SecretsFile.Read(file.Text!).PlainAdditions;
                }
                catch (Exception e) when (e is InvalidDataException or FormatException or JsonException or InvalidOperationException)
                {
                    return new(name, DoctorStatus.Fail, $"sealed envelope unreadable ({e.Message})", new ReviewUserSecrets(id), Kind: "sealed user secrets files that can't be read");
                }
                if (plain is null)
                    return null;
                var added = UserSecretsVault.FlattenKeys(plain);
                return new(name, DoctorStatus.Warn, $"sealed, but {added.Count} plaintext key(s) were added beside it; they are sealed on the next run",
                    new ReviewUserSecrets(id), Position.Plaintext, Position.SealedApproved, "sealed user secrets files with plaintext keys added beside them", KeyNames(added));
            default:
                return null;
        }
    }

    static DoctorCheck? Project(DoctorFile file)
    {
        if (file.Text is null || !UserSecretsId().IsMatch(file.Text))
            return null;
        return file.Text.Contains(ReferenceConfigurationPackage.Package, StringComparison.Ordinal)
            ? null
            : new($"project {file.Path}", DoctorStatus.Warn, "sets <UserSecretsId> but doesn't reference Tiresias.Extensions.Configuration, so its secrets.json stays plaintext",
                new ReferenceConfigurationPackage(file.Path), Position.Plaintext, Position.SealedApproved,
                "projects that set <UserSecretsId> but don't reference Tiresias.Extensions.Configuration");
    }

    static string Keys(int count) => count == 1 ? "1 key" : $"{count} keys";

    /// <summary>A file's key names, order aside: a dismissal bound to them lapses when a key is added.</summary>
    static string KeyNames(IEnumerable<string> keys) => string.Join('\n', keys.Order(StringComparer.Ordinal));

    static JsonNode? Parse(string text) =>
        JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

    [GeneratedRegex(@"<UserSecretsId>\s*[^<\s]+\s*</UserSecretsId>")]
    private static partial Regex UserSecretsId();
}
