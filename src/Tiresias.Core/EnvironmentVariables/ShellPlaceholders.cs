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

    readonly Dictionary<(ShellIdentity Shell, string Variable), (EnvironmentVariableAccess Access, string Token, DateTimeOffset ExpiresAt)> held = [];
    readonly List<string> replaced = [];
    readonly Lock gate = new();

    public Task<MintedPlaceholder> GetAsync(ShellIdentity shell, EnvironmentPlaceholder placeholder, Func<Task<MintedPlaceholder>> mint) =>
        GetAsync(shell, new EnvironmentVariableAccess(placeholder.Variable, Placeholder: placeholder), mint);

    public async Task<MintedPlaceholder> GetAsync(ShellIdentity shell, EnvironmentVariableAccess access, Func<Task<MintedPlaceholder>> mint)
    {
        var key = (shell, access.Name.ToUpperInvariant());
        lock (gate)
            if (held.TryGetValue(key, out var existing) && access.SameDelivery(existing.Access) && existing.ExpiresAt - time.GetUtcNow() > Margin)
                return new(existing.Token);
        var minted = await mint();
        lock (gate)
        {
            if (held.Remove(key, out var old))
                replaced.Add(old.Token);
            if (minted.Token is { } token)
                held[key] = (access, token, minted.ExpiresAt ?? time.GetUtcNow() + Consent.MaxDuration);
        }
        return minted;
    }

    /// <summary>Revoke a terminal's previous placeholders when the corresponding delivery is removed or remapped.</summary>
    public IReadOnlyList<string> ReleaseChanged(ShellIdentity shell, IReadOnlyDictionary<string, EnvironmentVariableAccess> current)
    {
        lock (gate)
        {
            var changed = held.Where(pair => pair.Key.Shell == shell
                && (!current.TryGetValue(pair.Key.Variable, out var access) || !access.SameDelivery(pair.Value.Access))).ToArray();
            foreach (var old in changed)
                held.Remove(old.Key);
            return [.. changed.Select(pair => pair.Value.Token)];
        }
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
