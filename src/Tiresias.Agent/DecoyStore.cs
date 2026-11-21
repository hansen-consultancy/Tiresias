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
        foreach (var step in steps)
            switch (step)
            {
                case WriteDecoyFile file:
                    Directory.CreateDirectory(Path.GetDirectoryName(file.Path)!);
                    using (var created = new FileStream(file.Path, FileMode.CreateNew, FileAccess.Write))
                    using (var writer = new StreamWriter(created))
                        writer.Write(file.Content);
                    break;
                case SetDecoyVariable variable:
                    Environment.SetEnvironmentVariable(variable.Name, variable.Value, EnvironmentVariableTarget.User);
                    break;
            }
        var placed = new PlacedDecoy(kind, where, DateTimeOffset.Now);
        Save(set.With(placed));
        return placed;
    }

    /// <summary>Removes every decoy placed and forgets the values. Returns what could not be removed, by path or name.</summary>
    public static IReadOnlyList<string> RemoveAll()
    {
        if (Current is not { } set)
            return [];
        var left = new List<string>();
        foreach (var placed in set.Placed)
        {
            foreach (var target in DecoyPlan.Undo(placed))
                try
                {
                    if (placed.Kind == DecoyKind.Variables)
                        Environment.SetEnvironmentVariable(target, null, EnvironmentVariableTarget.User);
                    else
                        File.Delete(target);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    left.Add(target);
                }
            // The project folder goes too, unless the user put something of their own in it.
            if (placed.Kind == DecoyKind.Project && Directory.Exists(placed.Where) && !Directory.EnumerateFileSystemEntries(placed.Where).Any())
                Directory.Delete(placed.Where);
        }
        if (left.Count == 0)
            File.Delete(FilePath);
        return left;
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
