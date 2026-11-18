using Tiresias.Protocol;

namespace Tiresias.UserSecrets;

/// <summary>What the agent does with one user-secrets load, before any file is written or prompt shown.</summary>
public enum UserSecretsAction
{
    /// <summary>Return the file as it is: plaintext the app could read anyway, so nothing is lost by serving it.</summary>
    ServeAsIs,
    /// <summary>First load of a plaintext file: seal it in place, then return the document. No prompt: the app could read the file a moment ago.</summary>
    SealAndServe,
    /// <summary>Sealed: show the consent screen first.</summary>
    AskConsent,
    /// <summary>Sealed, and the user already allowed this executable for this session.</summary>
    Serve,
    Deny,
    Error,
}

/// <param name="Reseal">Plaintext keys sit beside the envelope (or the file is plain) and will be sealed once the document is open.</param>
/// <param name="Message">Why, for the reply and the log. Never a value.</param>
public sealed record UserSecretsPlan(UserSecretsAction Action, bool Reseal = false, string? Message = null);

/// <summary>
/// The decisions of the user-secrets agent, separate from the pipe, the files and the dialog. A
/// sealed file is never opened while locked; a plaintext one is served as it is while locked (the
/// app could read it anyway) and sealed on the first load while unlocked, provided a recovery key
/// exists, so no file ever depends on the TPM alone.
/// </summary>
public static class UserSecretsPolicy
{
    public const string LockedMessage = "Tiresias is locked. Unlock it from the tray icon (or run tir unlock), then start the app again.";

    public static UserSecretsPlan Decide(SecretsFileKind kind, bool hasPlainAdditions, bool unlocked, bool recoveryKeySet, bool remembered) => kind switch
    {
        SecretsFileKind.None => new(UserSecretsAction.ServeAsIs),
        SecretsFileKind.Invalid => new(UserSecretsAction.Error, Message: "secrets.json is not valid JSON. Fix or delete the file, then start the app again."),
        SecretsFileKind.Plain when !unlocked => new(UserSecretsAction.ServeAsIs, Message: "Locked: served the plaintext file unchanged; it is sealed on the first load after you unlock."),
        SecretsFileKind.Plain when !recoveryKeySet => new(UserSecretsAction.ServeAsIs, Message: "No recovery key yet: served the plaintext file unchanged. Create the recovery key so the file can be sealed."),
        SecretsFileKind.Plain => new(UserSecretsAction.SealAndServe, Reseal: true),
        SecretsFileKind.Sealed when !unlocked => new(UserSecretsAction.Deny, Message: LockedMessage),
        SecretsFileKind.Sealed => new(remembered ? UserSecretsAction.Serve : UserSecretsAction.AskConsent, Reseal: hasPlainAdditions && recoveryKeySet),
        _ => new(UserSecretsAction.Error, Message: $"Unknown secrets file state {kind}."),
    };

    /// <summary>
    /// Refuses a request whose folder isn't <c>{root}\{UserSecretsId}</c>: the app names the folder,
    /// and the agent opens files only where user secrets live.
    /// </summary>
    /// <returns>The reason to refuse, or <c>null</c>.</returns>
    public static string? Validate(AgentRequest request, string userSecretsRoot)
    {
        if (request.Op != AgentRequest.LoadUserSecrets)
            return $"Unknown request '{request.Op}'.";
        if (string.IsNullOrWhiteSpace(request.UserSecretsId) || request.UserSecretsId.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || request.UserSecretsId is "." or "..")
            return "The UserSecretsId is not a valid folder name.";
        var expected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(userSecretsRoot, request.UserSecretsId)));
        var actual = Path.TrimEndingDirectorySeparator(Path.GetFullPath(request.SecretsDirectory));
        return string.Equals(expected, actual, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
            ? null
            : "The secrets folder is not where user secrets live for this UserSecretsId.";
    }
}
