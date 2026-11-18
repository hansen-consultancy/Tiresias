using Tiresias.Access;

namespace Tiresias.EnvironmentVariables;

/// <summary>
/// The placeholders each terminal holds, one per variable, so changing folder doesn't mint a new
/// one each time. A placeholder close to the expiry the broker gave it (the lease's end, often well
/// before the 10 h asked for) is minted again. <see cref="Release"/> hands back,
/// for revoking, the ones replaced since and those of terminals that exited (or all of them when
/// the agent locks).
/// </summary>
public sealed class ShellPlaceholders(TimeProvider time)
{
    /// <summary>Minted again when less than this is left, so a terminal's next folder change refreshes it.</summary>
    static readonly TimeSpan Margin = TimeSpan.FromMinutes(30);

    readonly Dictionary<(ShellIdentity Shell, string Variable), (string Token, DateTimeOffset ExpiresAt)> held = [];
    readonly List<string> replaced = [];
    readonly Lock gate = new();

    public async Task<MintedPlaceholder> GetAsync(ShellIdentity shell, EnvironmentPlaceholder placeholder, Func<Task<MintedPlaceholder>> mint)
    {
        var key = (shell, placeholder.Variable.ToUpperInvariant());
        lock (gate)
            if (held.TryGetValue(key, out var existing) && existing.ExpiresAt - time.GetUtcNow() > Margin)
                return new(existing.Token);
        var minted = await mint();
        lock (gate)
        {
            if (held.Remove(key, out var old))
                replaced.Add(old.Token);
            if (minted.Token is { } token)
                held[key] = (token, minted.ExpiresAt ?? time.GetUtcNow() + Consent.MaxDuration);
        }
        return minted;
    }

    /// <summary>Takes out the placeholders replaced since the last call and those of terminals no longer running.</summary>
    public IReadOnlyList<string> Release(Func<int, DateTime, bool> isRunning)
    {
        lock (gate)
        {
            var gone = held.Where(pair => !isRunning(pair.Key.Shell.ProcessId, pair.Key.Shell.Started)).ToArray();
            foreach (var pair in gone)
                held.Remove(pair.Key);
            string[] released = [.. replaced, .. gone.Select(pair => pair.Value.Token)];
            replaced.Clear();
            return released;
        }
    }
}
