using Tiresias.UserSecrets;

namespace Tiresias.EnvironmentVariables;

/// <summary>Remembers an approval for this program and variable only while their block history is current.</summary>
public sealed class NuGetConsent
{
    readonly ConsentMemory memory = new();

    public async Task<(NuGetOutcome Outcome, string? PolicyRefusal)> DecideAsync(string program, string variable, ReleasePolicy policy,
        Func<Task<ConsentAnswer>> ask, Func<Task<ReleasePolicy>> recheck)
    {
        if (policy.Refusal is { } refusal)
            return (NuGetOutcome.Denied, refusal);
        var known = memory.IsAllowed(program, variable, DateTimeOffset.UtcNow, scope: policy.Scope);
        var outcome = known ? NuGetOutcome.CoveredBySession : (await ask()) switch
        {
            ConsentAnswer.AllowOnce => NuGetOutcome.AllowedOnce,
            ConsentAnswer.AllowForSession => NuGetOutcome.AllowedForSession,
            _ => NuGetOutcome.Denied,
        };
        if ((await recheck()).RefusalSince(policy) is { } changed)
            return (NuGetOutcome.Denied, changed);
        if (outcome == NuGetOutcome.AllowedForSession)
            memory.Remember(program, variable, DateTimeOffset.MaxValue, scope: policy.Scope);
        return (outcome, null);
    }

    public void Clear() => memory.Clear();
}
