using System.Net;
using System.Net.Sockets;
using Tiresias.Decoys;

namespace Tiresias.Agent;

/// <summary>
/// The decoys on this machine (<c>decoys.json</c> beside the keyring): placing one writes only
/// what <see cref="DecoyPlan"/> allows, and removal takes away every file, folder and variable
/// Tiresias placed, nothing else.
/// </summary>
public static class DecoyStore
{
    public static string FilePath => Path.Combine(KeyringStore.Directory, DecoySet.FileName);

    /// <summary>The decoys placed here, or <c>null</c> when none have been.</summary>
    public static DecoySet? Current => File.Exists(FilePath) ? DecoySet.Parse(File.ReadAllText(FilePath)) : null;

    /// <summary>The default places: <c>passwords.txt</c> in Documents, and an old-looking project folder beside the user's code.</summary>
    public static string DefaultPath(DecoyKind kind) => kind switch
    {
        DecoyKind.PasswordsFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), DecoyPlan.PasswordsFileName),
        DecoyKind.Project => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "source", "billing-api-old"),
        _ => "",
    };

    /// <summary>Places one decoy, minting this install's values and ports the first time.</summary>
    /// <exception cref="InvalidOperationException">Something is already at that place.</exception>
    public static PlacedDecoy Place(DecoyKind kind, string? where)
    {
        where = kind == DecoyKind.Variables ? "user environment" : Path.GetFullPath(where ?? DefaultPath(kind));
        var set = Current ?? DecoySet.Mint(Free);
        var steps = DecoyPlan.Steps(set, kind, where, Exists);
        var applied = new List<DecoyStep>();
        try
        {
            foreach (var step in steps)
            {
                Apply(step);
                applied.Add(step);
            }
            var placed = new PlacedDecoy(kind, where, DateTimeOffset.Now);
            Save(set.With(placed));
            return placed;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Unrecorded decoys would never be removed, and the doctor would call them secrets: take back what was written.
            Revert(applied);
            if (kind == DecoyKind.Project && Directory.Exists(where) && !Directory.EnumerateFileSystemEntries(where).Any())
                Directory.Delete(where);
            throw;
        }
    }

    /// <summary>
    /// Removes every decoy placed and forgets the values. A file or variable changed since it was
    /// placed is the user's now: it is kept and forgotten. <c>Left</c> is what couldn't be removed
    /// (still remembered, to try again); <c>Kept</c> is what was changed.
    /// </summary>
    public static (IReadOnlyList<string> Left, IReadOnlyList<string> Kept) RemoveAll()
    {
        if (Current is not { } set)
            return ([], []);
        var left = new List<string>();
        var kept = new List<string>();
        foreach (var placed in set.Placed)
        {
            var (remove, changed) = DecoyPlan.Undo(set, placed, Read);
            kept.AddRange(changed);
            foreach (var step in remove)
                try
                {
                    Revert([step]);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    left.Add(step is WriteDecoyFile f ? f.Path : ((SetDecoyVariable)step).Name);
                }
            // The project folder goes too, unless the user put something of their own in it.
            if (placed.Kind == DecoyKind.Project && Directory.Exists(placed.Where) && !Directory.EnumerateFileSystemEntries(placed.Where).Any())
                try
                {
                    Directory.Delete(placed.Where);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    // Open in Explorer or a shell: try again next time.
                    left.Add(placed.Where);
                }
        }
        if (left.Count == 0)
            File.Delete(FilePath);
        return (left, kept);
    }

    static void Apply(DecoyStep step)
    {
        switch (step)
        {
            case WriteDecoyFile file:
                Directory.CreateDirectory(Path.GetDirectoryName(file.Path)!);
                var created = new FileStream(file.Path, FileMode.CreateNew, FileAccess.Write);
                try
                {
                    using var writer = new StreamWriter(created);
                    writer.Write(file.Content);
                }
                catch
                {
                    // Created here, so it is ours to take back.
                    created.Dispose();
                    File.Delete(file.Path);
                    throw;
                }
                break;
            case SetDecoyVariable variable:
                Environment.SetEnvironmentVariable(variable.Name, variable.Value, EnvironmentVariableTarget.User);
                break;
        }
    }

    static void Revert(IEnumerable<DecoyStep> steps)
    {
        foreach (var step in steps)
            if (step is WriteDecoyFile file)
                File.Delete(file.Path);
            else if (step is SetDecoyVariable variable)
                Environment.SetEnvironmentVariable(variable.Name, null, EnvironmentVariableTarget.User);
    }

    static string? Read(string pathOrVariable)
    {
        if (DecoyPlan.VariableNames.Contains(pathOrVariable))
            return Environment.GetEnvironmentVariable(pathOrVariable, EnvironmentVariableTarget.User);
        try
        {
            return File.Exists(pathOrVariable) ? File.ReadAllText(pathOrVariable) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Unreadable: treat it as changed, so it is never deleted unseen.
            return "";
        }
    }

    static bool Exists(string pathOrVariable) =>
        DecoyPlan.VariableNames.Contains(pathOrVariable)
            ? Environment.GetEnvironmentVariable(pathOrVariable, EnvironmentVariableTarget.User) is not null
            : Path.Exists(pathOrVariable);

    static bool Free(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    static void Save(DecoySet set)
    {
        Directory.CreateDirectory(KeyringStore.Directory);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, set.ToJson());
        File.Move(temp, FilePath, overwrite: true);
    }
}
