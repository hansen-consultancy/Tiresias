using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The <see cref="Dismissals"/> on disk (<c>dismissals.json</c> beside the keyring), shared by the app
/// and <c>tir doctor</c>. Holds finding names, hashes and the user's reasons, never a value.
/// </summary>
public static class DismissalStore
{
    static readonly Lock gate = new();

    static string FilePath => Path.Combine(KeyringStore.Directory, "dismissals.json");

    /// <summary>The dismissals, or none when the file is missing or unreadable.</summary>
    public static Dismissals Load()
    {
        lock (gate)
            return Read();
    }

    public static Dismissals Update(Func<Dismissals, Dismissals> change)
    {
        lock (gate)
        {
            var after = change(Read());
            Directory.CreateDirectory(KeyringStore.Directory);
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, after.ToJson());
            File.Move(temp, FilePath, overwrite: true);
            return after;
        }
    }

    static Dismissals Read()
    {
        try
        {
            return File.Exists(FilePath) ? Dismissals.Parse(File.ReadAllText(FilePath)) : Dismissals.Empty;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Dismissals.Empty;
        }
    }
}
