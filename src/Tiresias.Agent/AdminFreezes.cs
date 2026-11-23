using System.ComponentModel;
using Tiresias.Admin;
using Tiresias.AdminTier;

namespace Tiresias.Agent;

/// <summary>The tier's removal undoing the service's freezes itself, when the service didn't (docs/admin-tier.md, <i>Stopping the program</i>).</summary>
public static class AdminFreezes
{
    /// <summary>
    /// Run elevated, the service stopped: thaws every job in <c>frozen.json</c>, lifts its filters and
    /// removes Tiresias's filtering provider, then deletes the file. A job not found is one whose
    /// processes all ended; one that can't be thawed keeps the file.
    /// </summary>
    /// <returns>Whether nothing is left frozen or blocked; the file stays when something is.</returns>
    public static bool UndoAll(string stateFolder)
    {
        var path = Path.Combine(stateFolder, "frozen.json");
        // A damaged file names no filter to lift: the provider stays, its filters with it, and so does the file.
        if (AdminFrozen.Parse(File.Exists(path) ? File.ReadAllText(path) : null) is not { } frozen)
            return false;
        // Not all, so each job is tried; one still frozen keeps the file, for a later removal to retry.
        var thawed = frozen.Entries.Select(e => ProcessFreezer.Thaw(e.Job)).ToArray().All(t => t != JobThaw.Failed);
        try
        {
            if (!NetworkBlock.Lift(frozen.Entries.SelectMany(e => e.Filters)) || !NetworkBlock.RemoveProvider())
                return false;
        }
        catch (Win32Exception)
        {
            return false;
        }
        if (!thawed)
            return false;
        File.Delete(path);
        return true;
    }
}
