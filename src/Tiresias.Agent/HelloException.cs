namespace Tiresias.Agent;

public enum HelloProblem
{
    /// <summary>No PIN, face or fingerprint is set up for this Windows account.</summary>
    NotSetUp,
    /// <summary>The user closed the Hello prompt.</summary>
    Cancelled,
    /// <summary>The prompt was answered too late, typically after waiting unseen behind other windows.</summary>
    Expired,
    /// <summary>The Tiresias credential is gone (Hello reset, new PC): the recovery key re-wraps.</summary>
    CredentialMissing,
    /// <summary>Anything else Windows reported, e.g. the TPM is busy or locked out.</summary>
    Unavailable,
}

/// <summary>Windows Hello failed for a reason the caller may explain differently; still an <see cref="InvalidOperationException"/>.</summary>
public sealed class HelloException(HelloProblem problem, string message, Exception? inner = null) : InvalidOperationException(message, inner)
{
    public HelloProblem Problem { get; } = problem;
}
