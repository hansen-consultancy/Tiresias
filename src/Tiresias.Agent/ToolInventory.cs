using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The global tools listing (<see cref="ToolSnapshot"/>) on disk, <c>inventory.json</c> beside the
/// keyring, shared by the app, which keeps it a day fresh in the background, and <c>tir doctor --surface</c>.
/// </summary>
public static class ToolInventory
{
    static readonly Lock gate = new();

    static string FilePath => Path.Combine(KeyringStore.Directory, "inventory.json");

    /// <summary>
    /// Today's listing: the one on disk when it is under a day old, else a new one, saved. With
    /// <paramref name="refresh"/>, always a new one. Slow when it lists (seconds per package manager).
    /// </summary>
    public static ToolSnapshot Current(bool refresh = false)
    {
        lock (gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (!refresh && Read() is { } saved && !ToolSnapshot.IsDue(saved, now))
                return saved;
            var taken = new ToolSnapshot(now, [.. SurfaceProbe.GlobalTools()]);
            Write(taken);
            return taken;
        }
    }

    static ToolSnapshot? Read()
    {
        try
        {
            return File.Exists(FilePath) ? ToolSnapshot.Parse(File.ReadAllText(FilePath)) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>A unique temporary name: the app and <c>tir</c> may both be listing.</summary>
    static void Write(ToolSnapshot snapshot)
    {
        try
        {
            Directory.CreateDirectory(KeyringStore.Directory);
            var temp = $"{FilePath}.{Guid.NewGuid():N}.tmp";
            File.WriteAllText(temp, snapshot.ToJson());
            File.Move(temp, FilePath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Not saved: the next run lists again.
        }
    }
}
