using System.Text.Json;
using Tiresias.Audit;
using Tiresias.Protocol;
using Tiresias.Vault;

namespace Tiresias.UserSecrets;

/// <summary>The keys the agent holds right now.</summary>
public interface IUserSecretsKeys
{
    /// <summary>The open Hello wrapper while unlocked; <c>null</c> while locked.</summary>
    IKeyWrapper? Unlocked { get; }

    /// <summary>The recovery key's public wrapper, or <c>null</c> when none is set.</summary>
    IKeyWrapper? Recovery { get; }
}

/// <summary>Shows a consent screen (a dialog in the app, a y/N line in <c>tir agent</c>).</summary>
public interface IUserSecretsConsentPrompt
{
    /// <summary>Cancelled when the screen times out or the agent locks; the service treats that as a refusal.</summary>
    Task<ConsentAnswer> AskAsync(UserSecretsConsentRequest request, CancellationToken ct);

    /// <summary>
    /// Tiresias is locked and a program asks for a sealed file: offer to unlock rather than refuse.
    /// Completes with whether the user unlocked. The default declines, so a prompt that can't unlock
    /// (the console of <c>tir agent</c>) keeps answering "unlock first".
    /// </summary>
    /// <param name="executable">The program asking, or <c>null</c> when unknown.</param>
    Task<bool> AskUnlockAsync(string? executable, string userSecretsId, CancellationToken ct) => Task.FromResult(false);
}

/// <summary>
/// The agent's side of protected user secrets: answers one <see cref="AgentRequest"/> per
/// <see cref="UserSecretsPolicy"/>, reading and sealing <c>secrets.json</c> in place. Consent screens
/// are shown one at a time; a request that arrives while one is open waits its turn, and is
/// answered from memory if the user allowed the same program for the session meanwhile.
/// </summary>
public sealed class UserSecretsService : IDisposable
{
    /// <summary>Shorter than the client's own three-minute wait, so the app gets a reason rather than a timeout.</summary>
    public static readonly TimeSpan ConsentTimeout = TimeSpan.FromMinutes(2);

    /// <summary>The longest an "allow for this session" lasts even if the agent never locks.</summary>
    public static readonly TimeSpan SessionLength = TimeSpan.FromHours(12);

    readonly string userSecretsRoot;
    readonly IUserSecretsKeys keys;
    readonly IUserSecretsConsentPrompt prompt;
    readonly TimeProvider time;
    readonly AuditLog? audit;
    readonly ISecretReferenceResolver? references;
    readonly Func<string?, CancellationToken, Task<ReleasePolicy>> checkProgram;
    readonly SemaphoreSlim screen = new(1, 1);
    readonly Lock writeGate = new();
    CancellationTokenSource locked = new();

    /// <param name="audit">Where decisions are recorded (keys and programs only), or <c>null</c>.</param>
    /// <param name="references">Fetches what <c>tiresias:</c> values name, or <c>null</c> where nothing can (<c>tir agent</c> without a broker).</param>
    public UserSecretsService(string userSecretsRoot, IUserSecretsKeys keys, IUserSecretsConsentPrompt prompt, TimeProvider time, AuditLog? audit = null,
        ISecretReferenceResolver? references = null, Func<string?, CancellationToken, Task<ReleasePolicy>>? checkProgram = null)
    {
        this.references = references;
        this.checkProgram = checkProgram ?? ((_, _) => Task.FromResult(default(ReleasePolicy)));
        this.userSecretsRoot = userSecretsRoot;
        this.keys = keys;
        this.prompt = prompt;
        this.time = time;
        this.audit = audit;
    }

    public ConsentMemory Memory { get; } = new();

    /// <summary>One line per decision, for a log window. Never a value.</summary>
    public event Action<string>? Log;

    /// <summary>
    /// A plaintext file was sealed on its first load, without a prompt. Raised with the UserSecretsId
    /// so the app can tell the user something changed: from now on that project asks first.
    /// </summary>
    public event Action<string>? FirstSealed;

    /// <summary>Forgets every "allow for this session" and refuses the consent screen that is open, if any.</summary>
    public void Lock()
    {
        Memory.Clear();
        var previous = Interlocked.Exchange(ref locked, new CancellationTokenSource());
        // Not disposed: a request may be reading its token right now. One small object per lock.
        previous.Cancel();
    }

    /// <param name="caller">Image path of the process on the pipe, or <c>null</c> when unknown.</param>
    public async Task<AgentReply> HandleAsync(AgentRequest request, string? caller, CancellationToken ct)
    {
        try
        {
            return await HandleCoreAsync(request, caller, ct);
        }
        catch (Exception e) when (e is InvalidDataException or JsonException or FormatException or IOException or UnauthorizedAccessException or InvalidOperationException or ObjectDisposedException)
        {
            Record(AuditKind.Deny, request, caller, $"error: {e.Message}");
            return new(AgentStatus.Error, Message: e.Message);
        }
    }

    async Task<AgentReply> HandleCoreAsync(AgentRequest request, string? caller, CancellationToken ct)
    {
        if (UserSecretsPolicy.Validate(request, userSecretsRoot) is { } invalid)
        {
            Record(AuditKind.Deny, request, caller, invalid);
            return new(AgentStatus.Error, Message: invalid);
        }

        AgentReply Refuse(string why)
        {
            Record(AuditKind.Deny, request, caller, why);
            return new(AgentStatus.Denied, Message: why);
        }

        var policy = await checkProgram(caller, ct);
        if (policy.Refusal is { } refusal)
            return Refuse(refusal);
        async Task<string?> Recheck() => (await checkProgram(caller, ct)).RefusalSince(policy);

        var path = Path.Combine(request.SecretsDirectory, SecretsFile.FileName);
        var text = File.Exists(path) ? await File.ReadAllTextAsync(path, ct) : null;
        var kind = SecretsFile.Classify(text);
        var additions = kind == SecretsFileKind.Sealed && SecretsFile.Read(text!).PlainAdditions is not null;
        var wrapper = keys.Unlocked;
        if (kind == SecretsFileKind.Sealed && wrapper is null)
        {
            if (await AskUnlockAsync(caller, request.UserSecretsId, ct))
                wrapper = keys.Unlocked;
            if (await Recheck() is { } changedWhileLocked)
                return Refuse(changedWhileLocked);
        }
        var plan = UserSecretsPolicy.Decide(kind, additions, wrapper is not null, keys.Recovery is not null,
            Memory.IsAllowed(caller, request.UserSecretsId, time.GetUtcNow(), scope: policy.Scope));

        switch (plan.Action)
        {
            case UserSecretsAction.ServeAsIs:
                // A reference served as is would reach the app as a connection string that can't work.
                if (text is not null && SecretsFile.NamesReferences(text))
                {
                    var fetchable = "this file names tiresias: values, which are fetched only once the file can be sealed; "
                        + (wrapper is null ? "unlock Tiresias, then start the app again" : "create the recovery key in the Tiresias app, then start the app again");
                    Record(AuditKind.Deny, request, caller, fetchable);
                    return new(AgentStatus.Error, Message: fetchable);
                }
                if (plan.Message is not null)
                    Say($"{request.UserSecretsId}: {plan.Message}");
                return await Recheck() is { } refused ? Refuse(refused) : new(AgentStatus.Ok, text);
            case UserSecretsAction.Deny:
                Record(AuditKind.Deny, request, caller, plan.Message);
                return new(AgentStatus.Denied, Message: plan.Message);
            case UserSecretsAction.Error:
                Record(AuditKind.Deny, request, caller, plan.Message);
                return new(AgentStatus.Error, Message: plan.Message);
        }

        var load = UserSecretsVault.Open(request.UserSecretsId, text, wrapper!);
        var requested = SecretReferences.Find(load.Document);
        var scope = requested.Count == 0 ? "" : JsonSerializer.Serialize(requested
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .ThenBy(item => item.Reference.ToString(), StringComparer.Ordinal)
            .Select(item => new { item.Key, item.Reference }));
        string reason;
        if (plan.Action == UserSecretsAction.AskConsent || requested.Count > 0)
        {
            var referenced = requested.Select(item => item.Key).ToHashSet(StringComparer.Ordinal);
            var entries = load.Keys.Where(key => !referenced.Contains(key))
                .Concat(requested.Select(item => $"{item.Key} → {item.Reference}")).ToArray();
            var (answer, why) = await AskAsync(new(caller, request.UserSecretsId, entries), scope, policy.Scope, ct);
            if (await Recheck() is { } changed)
                return Refuse(changed);
            if (answer == ConsentAnswer.Deny)
            {
                Record(AuditKind.Deny, request, caller, why);
                return new(AgentStatus.Denied, Message: why);
            }
            reason = why;
        }
        else
            reason = plan.Action == UserSecretsAction.SealAndServe ? "first load, sealed in place" : "allowed for this session";

        if (plan.Reseal)
        {
            var sealedText = UserSecretsVault.Seal(request.UserSecretsId, load.Version + 1, load.Document, [wrapper!, keys.Recovery!]);
            lock (writeGate)
            {
                var temp = path + ".tiresias.tmp";
                File.WriteAllText(temp, sealedText);
                File.Move(temp, path, overwrite: true);
            }
            Say($"{request.UserSecretsId}: sealed {load.PlaintextKeys.Count} plaintext key(s).");
            if (plan.Action == UserSecretsAction.SealAndServe)
                FirstSealed?.Invoke(request.UserSecretsId);
        }
        DateTimeOffset? refreshAt;
        try
        {
            refreshAt = await SecretReferences.ResolveAsync(load.Document, time.GetUtcNow(), async (key, reference) =>
            {
                try
                {
                    return references is null
                        ? throw new InvalidOperationException("only the Tiresias app can fetch it")
                        : await references.ResolveAsync(reference, caller, request.UserSecretsId, ct);
                }
                catch (InvalidOperationException e)
                {
                    throw new InvalidOperationException($"{key} ({reference}): {e.Message}", e);
                }
            });
        }
        catch (Exception e) when (e is InvalidOperationException or InvalidDataException)
        {
            Record(AuditKind.Deny, request, caller, e.Message);
            return new(AgentStatus.Error, Message: e.Message);
        }
        if (await Recheck() is { } finalRefusal)
            return Refuse(finalRefusal);
        Record(AuditKind.Allow, request, caller, $"{reason}; {load.Keys.Count} key(s)");
        return new(AgentStatus.Ok, load.Document.ToJsonString(), RefreshAt: refreshAt?.ToUnixTimeSeconds());
    }

    /// <summary>Takes its turn with the consent screens; another request may have unlocked meanwhile.</summary>
    async Task<bool> AskUnlockAsync(string? caller, string userSecretsId, CancellationToken ct)
    {
        using var timeout = new CancellationTokenSource(ConsentTimeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        try
        {
            await screen.WaitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        try
        {
            return keys.Unlocked is not null || (await prompt.AskUnlockAsync(caller, userSecretsId, linked.Token) && keys.Unlocked is not null);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        finally
        {
            screen.Release();
        }
    }

    async Task<(ConsentAnswer Answer, string Reason)> AskAsync(UserSecretsConsentRequest consent, string scope, ReleaseScope revision, CancellationToken ct)
    {
        using var timeout = new CancellationTokenSource(ConsentTimeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token, locked.Token);
        try
        {
            await screen.WaitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            return (ConsentAnswer.Deny, Refusal(timeout, ct));
        }
        try
        {
            // The user may have allowed this program for the session while this request waited.
            if ((await checkProgram(consent.Executable, linked.Token)).RefusalSince(new(revision)) is { } refusal)
                return (ConsentAnswer.Deny, refusal);
            if (Memory.IsAllowed(consent.Executable, consent.UserSecretsId, time.GetUtcNow(), scope, revision))
                return (ConsentAnswer.AllowOnce, "allowed for this session");
            var answer = await prompt.AskAsync(consent, linked.Token);
            if (answer == ConsentAnswer.AllowForSession)
                Memory.Remember(consent.Executable, consent.UserSecretsId, time.GetUtcNow() + SessionLength, scope, revision);
            return answer switch
            {
                ConsentAnswer.Deny => (answer, "You declined on the Tiresias consent screen."),
                ConsentAnswer.AllowForSession => (answer, "allowed for this session on the consent screen"),
                _ => (answer, "allowed once on the consent screen"),
            };
        }
        catch (OperationCanceledException)
        {
            return (ConsentAnswer.Deny, Refusal(timeout, ct));
        }
        finally
        {
            screen.Release();
        }
    }

    static string Refusal(CancellationTokenSource timeout, CancellationToken ct) =>
        timeout.IsCancellationRequested ? $"Nobody answered the Tiresias consent screen within {ConsentTimeout.TotalMinutes:0} minutes. Start the app again to get a new one."
        : ct.IsCancellationRequested ? "The app stopped waiting for consent."
        : UserSecretsPolicy.LockedMessage;

    void Record(AuditKind kind, AgentRequest request, string? caller, string? reason)
    {
        Say($"{(kind == AuditKind.Allow ? "Allowed" : "Refused")} {request.UserSecretsId} to {caller ?? "an unknown program"}: {reason}");
        audit?.Append(new(kind, Consumer: "usersecrets", Service: UserSecretsVault.Slug(request.UserSecretsId), Reason: reason, Process: caller));
    }

    void Say(string message) => Log?.Invoke(message);

    public void Dispose()
    {
        screen.Dispose();
        locked.Dispose();
    }
}
