using System.Security.Cryptography;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// The app's <see cref="Blocklist"/>, kept in <c>blocklist.json</c> beside the activity log: asked
/// about every request before a dialog shows, changed by "This wasn't me", an unlock from the app
/// and the status page's Unblock. Thread-safe; each change is saved before it is announced.
/// </summary>
sealed class ProgramGuard
{
    readonly string path = Path.Combine(KeyringStore.Directory, "blocklist.json");
    readonly Lock gate = new();
    readonly Dictionary<string, (DateTime Written, long Length, string? Sha256)> hashes = new(StringComparer.OrdinalIgnoreCase);
    Blocklist list;

    public ProgramGuard()
    {
        try
        {
            list = Blocklist.Parse(File.Exists(path) ? File.ReadAllText(path) : null);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "reading the blocklist");
            list = Blocklist.Parse("");
        }
    }

    /// <summary>Raised after any change, on the thread that made it.</summary>
    public event Action? Changed;

    public Blocklist Current
    {
        get
        {
            lock (gate)
                return list;
        }
    }

    public GateDecision Decide(string? program) => Current.Decide(program, Sha256);

    /// <summary>Refuse everything from now on; the program is blocked later by <see cref="Block"/>, once its file is hashed.</summary>
    public void LockDown() => Change(l => l with { LockedDown = true });

    public void Block(string? program, string? sha256) => Change(l => l.Escalate(program, sha256, DateTimeOffset.Now));

    /// <summary>A decoy was used: block the program, without a lockdown.</summary>
    public void BlockForDecoy(string? program, string? sha256) => Change(l => l.Block(program, sha256, DateTimeOffset.Now));

    public void Unlocked()
    {
        if (Current.LockedDown)
            Change(l => l.Unlocked());
    }

    public void Unblock(string program) => Change(l => l.Unblock(program));

    void Change(Func<Blocklist, Blocklist> change)
    {
        lock (gate)
        {
            list = change(list);
            try
            {
                var temp = path + ".tmp";
                File.WriteAllText(temp, list.ToJson());
                File.Move(temp, path, overwrite: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Still enforced for as long as the app runs.
                AppLog.Error(e, "saving the blocklist");
            }
        }
        Changed?.Invoke();
    }

    /// <summary>The file's SHA-256 (hex), remembered while its size and time stay the same; <c>null</c> when it can't be read.</summary>
    public string? Sha256(string program)
    {
        try
        {
            var file = new FileInfo(program);
            if (!file.Exists)
                return null;
            lock (hashes)
                if (hashes.TryGetValue(program, out var known) && known.Written == file.LastWriteTimeUtc && known.Length == file.Length)
                    return known.Sha256;
            using var stream = file.OpenRead();
            var sha = Convert.ToHexString(SHA256.HashData(stream));
            lock (hashes)
                hashes[program] = (file.LastWriteTimeUtc, file.Length, sha);
            return sha;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }
}
