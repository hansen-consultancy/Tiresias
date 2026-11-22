using Tiresias.UserSecrets;

namespace Tiresias.EnvironmentVariables;

/// <summary>Remembers an approval for one program, feed, username and variable while its block history is current.</summary>
public sealed class NuGetConsent
{
    readonly Lock gate = new();
    readonly Dictionary<NuGetSource, ConsentMemory> feeds = [];

    /// <summary>Finds this request's mapping and drops grants for mappings or variables that disappeared.</summary>
    public NuGetSource? Match(SealedEnvironment environment, Uri uri)
    {
        lock (gate)
        {
            foreach (var previous in feeds.Keys.Where(s => !environment.NuGetSources.Contains(s)
                || !environment.Global.Any(v => string.Equals(v.Name, s.Variable, StringComparison.OrdinalIgnoreCase))).ToArray())
                feeds.Remove(previous);
        }
        return environment.NuGetSourceFor(uri);
    }

    /// <summary>A caller that supplies only a variable can authorize its current request once.</summary>
    public async Task<(NuGetOutcome Outcome, string? PolicyRefusal)> DecideAsync(string program, string variable, ReleasePolicy policy,
        Func<Task<ConsentAnswer>> ask, Func<Task<ReleasePolicy>> recheck)
    {
        if (policy.Refusal is { } refusal)
            return (NuGetOutcome.Denied, refusal);
        var answer = await ask();
        if ((await recheck()).RefusalSince(policy) is { } changed)
            return (NuGetOutcome.Denied, changed);
        return (answer is ConsentAnswer.AllowOnce or ConsentAnswer.AllowForSession ? NuGetOutcome.AllowedOnce : NuGetOutcome.Denied, null);
    }

    public async Task<(NuGetOutcome Outcome, string? PolicyRefusal)> DecideAsync(string program, NuGetSource source, ReleasePolicy policy,
        Func<Task<ConsentAnswer>> ask, Func<Task<ReleasePolicy>> recheck, Action ensureCurrent)
    {
        if (policy.Refusal is { } refusal)
            return (NuGetOutcome.Denied, refusal);
        ConsentMemory memory;
        lock (gate)
            if (!feeds.TryGetValue(source, out memory!))
                feeds[source] = memory = new();
        var known = memory.IsAllowed(program, source.Variable, DateTimeOffset.UtcNow, scope: policy.Scope);
        var outcome = known ? NuGetOutcome.CoveredBySession : (await ask()) switch
        {
            ConsentAnswer.AllowOnce => NuGetOutcome.AllowedOnce,
            ConsentAnswer.AllowForSession => NuGetOutcome.AllowedForSession,
            _ => NuGetOutcome.Denied,
        };
        if ((await recheck()).RefusalSince(policy) is { } changed)
            return (NuGetOutcome.Denied, changed);
        if (outcome == NuGetOutcome.Denied)
            return (outcome, null);
        ensureCurrent();
        lock (gate)
        {
            if (feeds.GetValueOrDefault(source) != memory)
                return (NuGetOutcome.Denied, "The NuGet approval is no longer current. Request access again.");
            if (outcome == NuGetOutcome.AllowedForSession)
                memory.Remember(program, source.Variable, DateTimeOffset.MaxValue, scope: policy.Scope);
        }
        return (outcome, null);
    }

    public void Clear()
    {
        lock (gate)
            feeds.Clear();
    }
}
