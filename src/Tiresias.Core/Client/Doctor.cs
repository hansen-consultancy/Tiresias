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

public sealed record DoctorCheck(string Name, DoctorStatus Status, string Detail);

/// <summary>What the vault file says about recoverability: which secrets lack a Hello or a recovery wrap.</summary>
public sealed record DoctorVault(int Secrets, IReadOnlyList<string> WithoutHello, IReadOnlyList<string> WithoutRecovery);

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
        return checks;
    }

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
        return new(name, DoctorStatus.Ok, $"{vault.Secrets} secrets, all with Hello and recovery wraps");
    }

    /// <returns><c>null</c> for an empty file or one that is sealed and clean: nothing to report per file.</returns>
    static DoctorCheck? UserSecretsFile(DoctorFile file)
    {
        var name = $"user secrets {file.Path}";
        switch (SecretsFile.Classify(file.Text))
        {
            case SecretsFileKind.Plain:
                var keys = UserSecretsVault.FlattenKeys(Parse(file.Text!)).Count;
                return new(name, DoctorStatus.Fail, $"plaintext, {keys} key(s) readable by anything running as you; run the app once with Tiresias.Extensions.Configuration to seal it");
            case SecretsFileKind.Invalid:
                return new(name, DoctorStatus.Fail, "not valid JSON; apps reading it will fail at startup");
            case SecretsFileKind.Sealed:
                JsonObject? plain;
                try
                {
                    plain = SecretsFile.Read(file.Text!).PlainAdditions;
                }
                catch (Exception e) when (e is InvalidDataException or FormatException or JsonException or InvalidOperationException)
                {
                    return new(name, DoctorStatus.Fail, $"sealed envelope unreadable ({e.Message})");
                }
                return plain is null
                    ? null
                    : new(name, DoctorStatus.Warn, $"sealed, but {UserSecretsVault.FlattenKeys(plain).Count} plaintext key(s) were added beside it; they are sealed on the next run");
            default:
                return null;
        }
    }

    static DoctorCheck? Project(DoctorFile file)
    {
        if (file.Text is null || !UserSecretsId().IsMatch(file.Text))
            return null;
        return file.Text.Contains("Tiresias.Extensions.Configuration", StringComparison.Ordinal)
            ? null
            : new($"project {file.Path}", DoctorStatus.Warn, "sets <UserSecretsId> but doesn't reference Tiresias.Extensions.Configuration, so its secrets.json stays plaintext");
    }

    static JsonNode? Parse(string text) =>
        JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

    [GeneratedRegex(@"<UserSecretsId>\s*[^<\s]+\s*</UserSecretsId>")]
    private static partial Regex UserSecretsId();
}
