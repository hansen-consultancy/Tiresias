namespace Tiresias.EnvironmentVariables;

/// <summary>A terminal's shell process. The start time tells it apart from a later process given the same id.</summary>
public sealed record ShellIdentity(int ProcessId, DateTime Started, string Program);

public enum ShellAnswer
{
    /// <summary>Every name was allowed in this shell before: hand them over without asking.</summary>
    Give,
    /// <summary>Some names are new to this shell: ask about those.</summary>
    Ask,
    /// <summary>Some names are new, but the user said no in this shell: hand over the others, and don't ask until they say so.</summary>
    Refused,
}

/// <summary>
/// Consent once per shell session: the names each terminal was allowed, remembered until the shell
/// exits or the agent locks. Changing to a folder whose set adds names asks about those alone.
/// A refusal sticks to that shell, so a <c>cd</c> doesn't ask again, until the user asks for it;
/// what the shell was allowed before it stays allowed.
/// </summary>
public sealed class ShellConsent
{
    readonly Lock gate = new();
    readonly Dictionary<(int, DateTime), (HashSet<string> Allowed, bool Refused)> shells = [];

    /// <param name="askAgain">The user asked for the prompt again, overriding an earlier no.</param>
    /// <returns>What to do, and the names the shell hasn't been allowed yet (empty for <see cref="ShellAnswer.Give"/>).</returns>
    public (ShellAnswer Answer, IReadOnlyList<string> New) Check(ShellIdentity shell, IEnumerable<string> names, bool askAgain = false)
    {
        lock (gate)
        {
            var known = shells.GetValueOrDefault(Key(shell));
            var allowed = known.Allowed ?? [];
            string[] fresh = [.. names.Where(n => !allowed.Contains(n))];
            if (fresh.Length == 0)
                return (ShellAnswer.Give, []);
            return (known.Refused && !askAgain ? ShellAnswer.Refused : ShellAnswer.Ask, fresh);
        }
    }

    public void Allow(ShellIdentity shell, IEnumerable<string> names)
    {
        lock (gate)
        {
            var allowed = shells.GetValueOrDefault(Key(shell)).Allowed ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            allowed.UnionWith(names);
            shells[Key(shell)] = (allowed, false);
        }
    }

    /// <summary>Remembers the no; what the shell was allowed before stays allowed.</summary>
    public void Refuse(ShellIdentity shell)
    {
        lock (gate)
            shells[Key(shell)] = (shells.GetValueOrDefault(Key(shell)).Allowed ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase), true);
    }

    /// <summary>Whether this shell said no, for a check made before anything is unlocked.</summary>
    public bool HasRefused(ShellIdentity shell)
    {
        lock (gate)
            return shells.GetValueOrDefault(Key(shell)).Refused;
    }

    /// <summary>The agent locked: every terminal asks again.</summary>
    public void Clear()
    {
        lock (gate)
            shells.Clear();
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

    static (int, DateTime) Key(ShellIdentity shell) => (shell.ProcessId, shell.Started);
}
