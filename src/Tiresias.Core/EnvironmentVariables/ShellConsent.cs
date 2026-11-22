using Tiresias.UserSecrets;

namespace Tiresias.EnvironmentVariables;

/// <summary>A terminal's shell process. The start time tells it apart from a later process given the same id.</summary>
public sealed record ShellIdentity(int ProcessId, DateTime Started, string Program);

public enum ShellAnswer
{
    /// <summary>The shell already has approval for every requested delivery.</summary>
    Give,
    /// <summary>Ask about new or changed deliveries.</summary>
    Ask,
    /// <summary>The user declined in this shell. Give only the deliveries whose approvals still match.</summary>
    Refused,
}

/// <summary>
/// Remembers each terminal's approvals while the same deliveries remain in its effective environment.
/// New names, folder overrides and changed routes ask again. A refusal stays quiet until the terminal asks again.
/// </summary>
public sealed class ShellConsent
{
    readonly Lock gate = new();
    readonly Dictionary<(int, DateTime, ReleaseScope), (Dictionary<string, EnvironmentVariableAccess> Allowed, bool Refused)> shells = [];

    /// <param name="askAgain">The user asked for the prompt again, overriding an earlier no.</param>
    /// <returns>What to do, and the names the shell hasn't been allowed yet (empty for <see cref="ShellAnswer.Give"/>).</returns>
    public (ShellAnswer Answer, IReadOnlyList<string> New) Check(ShellIdentity shell, IEnumerable<string> names, bool askAgain = false, ReleaseScope scope = default)
    {
        var (answer, fresh) = Check(shell, names.Select(n => new EnvironmentVariableAccess(n)), askAgain, scope);
        return (answer, [.. fresh.Select(a => a.Name)]);
    }

    public (ShellAnswer Answer, IReadOnlyList<EnvironmentVariableAccess> New) Check(ShellIdentity shell, IEnumerable<EnvironmentVariableAccess> requested,
        bool askAgain = false, ReleaseScope scope = default)
    {
        lock (gate)
        {
            var known = shells.GetValueOrDefault(Key(shell, scope));
            List<EnvironmentVariableAccess> fresh = [];
            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in requested)
                if (known.Allowed is not null && known.Allowed.TryGetValue(item.Name, out var previous) && item.SameDelivery(previous))
                    covered.Add(item.Name);
                else
                    fresh.Add(item);
            if (known.Allowed is { } allowed)
                foreach (var removed in allowed.Keys.Where(name => !covered.Contains(name)).ToArray())
                    allowed.Remove(removed);
            if (fresh.Count == 0)
                return (ShellAnswer.Give, []);
            return (known.Refused && !askAgain ? ShellAnswer.Refused : ShellAnswer.Ask, fresh);
        }
    }

    public void Allow(ShellIdentity shell, IEnumerable<string> names, ReleaseScope scope = default) =>
        Allow(shell, names.Select(n => new EnvironmentVariableAccess(n)), scope);

    public void Allow(ShellIdentity shell, IEnumerable<EnvironmentVariableAccess> requested, ReleaseScope scope = default)
    {
        lock (gate)
        {
            var allowed = shells.GetValueOrDefault(Key(shell, scope)).Allowed ?? new Dictionary<string, EnvironmentVariableAccess>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in requested)
                allowed[item.Name] = item;
            shells[Key(shell, scope)] = (allowed, false);
        }
    }

    /// <summary>Remembers the no; what the shell was allowed before stays allowed.</summary>
    public void Refuse(ShellIdentity shell, ReleaseScope scope = default)
    {
        lock (gate)
            shells[Key(shell, scope)] = (shells.GetValueOrDefault(Key(shell, scope)).Allowed ?? new Dictionary<string, EnvironmentVariableAccess>(StringComparer.OrdinalIgnoreCase), true);
    }

    /// <summary>Whether this shell said no, for a check made before anything is unlocked.</summary>
    public bool HasRefused(ShellIdentity shell, ReleaseScope scope = default)
    {
        lock (gate)
            return shells.GetValueOrDefault(Key(shell, scope)).Refused;
    }

    /// <summary>The agent locked: every terminal asks again.</summary>
    public void Clear()
    {
        lock (gate)
            shells.Clear();
    }

    /// <summary>Checks the program before preparing credentials and again after any asynchronous placeholder mint.</summary>
    public static async Task<(Delivery? Delivery, string? Refusal)> ReleaseAsync(ReleasePolicy approved, Func<Task<ReleasePolicy>> check,
        Func<Task<Delivery>> prepare)
    {
        if ((await check()).RefusalSince(approved) is { } refused)
            return (null, refused);
        var prepared = await prepare();
        return (await check()).RefusalSince(approved) is { } changed ? (null, changed) : (prepared, null);
    }

    /// <summary>Drops shells that have exited, so the table doesn't grow and a reused process id starts afresh.</summary>
    public void Prune(Func<int, DateTime, bool> isRunning)
    {
        lock (gate)
            foreach (var key in shells.Keys.Where(k => !isRunning(k.Item1, k.Item2)).ToArray())
                shells.Remove(key);
    }

    public int Count
    {
        get
        {
            lock (gate)
                return shells.Count;
        }
    }

    static (int, DateTime, ReleaseScope) Key(ShellIdentity shell, ReleaseScope scope) => (shell.ProcessId, shell.Started, scope);
}
