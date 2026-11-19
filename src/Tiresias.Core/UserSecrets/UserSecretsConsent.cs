namespace Tiresias.UserSecrets;

/// <summary>The user's answer on a consent screen.</summary>
public enum ConsentAnswer
{
    Deny,
    AllowOnce,
    /// <summary>Allow this executable again without asking until the agent locks or the session ends.</summary>
    AllowForSession,
}

/// <summary>
/// What a user-secrets consent screen shows: who asks and which keys they would get. Never values.
/// </summary>
/// <param name="Executable">Image path of the process on the pipe, as the agent saw it; <c>null</c> when it couldn't tell.</param>
public sealed record UserSecretsConsentRequest(string? Executable, string UserSecretsId, IReadOnlyList<string> Keys)
{
    /// <summary>Plain-text lines, so the dialog, the terminal agent and the log say the same thing.</summary>
    public IReadOnlyList<string> Describe() =>
    [
        $"Program:      {Executable ?? "unknown (the agent could not identify it)"}",
        $"Secrets id:   {UserSecretsId}",
        $"Keys ({Keys.Count}):    {(Keys.Count == 0 ? "none" : string.Join(", ", Keys))}",
    ];
}

/// <summary>
/// Remembered "allow for this session" answers, by executable and secrets id, each with an expiry.
/// An unidentified executable is never remembered: there is nothing to match the next request to.
/// Thread-safe.
/// </summary>
public sealed class ConsentMemory
{
    readonly Dictionary<(string Executable, string Id, string ReferenceScope), DateTimeOffset> allowed = [];
    readonly Lock gate = new();

    public void Remember(string? executable, string userSecretsId, DateTimeOffset until, string referenceScope = "")
    {
        if (executable is null)
            return;
        lock (gate)
            allowed[(Key(executable), userSecretsId, referenceScope)] = until;
    }

    public bool IsAllowed(string? executable, string userSecretsId, DateTimeOffset now, string referenceScope = "")
    {
        if (executable is null)
            return false;
        lock (gate)
        {
            if (!allowed.TryGetValue((Key(executable), userSecretsId, referenceScope), out var until))
                return false;
            if (until > now)
                return true;
            allowed.Remove((Key(executable), userSecretsId, referenceScope));
            return false;
        }
    }

    /// <summary>Forgets everything: the agent locked.</summary>
    public void Clear()
    {
        lock (gate)
            allowed.Clear();
    }

    /// <summary>Windows paths are case-insensitive; the same program must match however it was spelled.</summary>
    static string Key(string executable) => OperatingSystem.IsWindows() ? executable.ToUpperInvariant() : executable;
}
