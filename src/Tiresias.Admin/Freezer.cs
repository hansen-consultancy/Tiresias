using System.ComponentModel;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Tiresias.AdminTier;

namespace Tiresias.Admin;

/// <summary>
/// The service's freezes (docs/admin-tier.md, <i>Stopping the program</i>): each one a job of
/// frozen processes (<see cref="ProcessFreezer"/>) and filters blocking the program's network
/// (<see cref="NetworkBlock"/>), kept in <c>frozen.json</c> so a restart can still thaw them. While
/// that file can't be read the service freezes nothing, rather than lose track of a freeze.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
sealed class Freezer(string stateFolder, ILogger logger)
{
    readonly string path = Path.Combine(stateFolder, "frozen.json");
    readonly Lock gate = new();
    AdminFrozen? frozen;
    bool loaded;
    bool tornDown;

    /// <summary>Freezes the process and its descendants, and blocks the program's network.</summary>
    /// <returns>What was done (no process, when all were frozen already), or why nothing was.</returns>
    public (AdminFreezeResult? Done, string? Refusal) Freeze(string userSid, int pid)
    {
        lock (gate)
        {
            if (tornDown)
                return (null, "the admin tier is being removed");
            if (State() is not { } state)
                return (null, "the admin tier's record of freezes can't be read");
            var (processes, refusal) = AdminFreeze.Plan(pid, ProcessFreezer.Running(), userSid, Environment.ProcessId, Folders(userSid), state.Processes);
            if (refusal == AdminFreeze.AlreadyFrozen)
                return (new(0, true), null);
            if (refusal is not null)
                return (null, $"the process {refusal}");
            var job = AdminFreeze.JobName(Guid.NewGuid());
            if (ProcessFreezer.Freeze(job, processes) == 0)
                return (null, "the process couldn't be frozen");
            var program = processes[0].Image;
            IReadOnlyList<ulong> filters = [];
            var blocked = state.Blocked(program);
            if (!blocked)
            {
                try
                {
                    filters = NetworkBlock.Block(program);
                    blocked = true;
                }
                catch (Win32Exception e)
                {
                    logger.LogError("A frozen program's network can't be blocked ({Code})", e.NativeErrorCode);
                }
            }
            // A freeze the record doesn't hold could never be found again to thaw: undo it instead.
            if (!Save(state.Add(new(state.NextId, userSid, program, job, processes, filters, DateTimeOffset.Now))))
            {
                Undo(job, processes.Count);
                Lift(filters);
                return (null, "the admin tier's record of freezes can't be written");
            }
            return (new(processes.Count, blocked), null);
        }
    }

    /// <summary>Thaws the user's freezes of the program and lifts the filters no other freeze needs.</summary>
    public (AdminThawResult? Done, string? Refusal) Thaw(string userSid, string program)
    {
        lock (gate)
        {
            if (State() is not { } state)
                return (null, "the admin tier's record of freezes can't be read");
            var (thawed, lift, left) = state.Thaw(userSid, program);
            var count = thawed.Sum(e => Undo(e.Job, e.Processes.Count));
            // Filters only the record can name: kept in it until lifted, so a later thaw or the removal retries them.
            if (!Lift(lift))
                return (null, "the program's network block can't be lifted");
            // Left recorded, a lifted filter would still read as blocking: refuse, and a retry rewrites it.
            if (!Save(left))
                return (null, "the admin tier's record of freezes can't be written");
            return (new(count), null);
        }
    }

    /// <summary>Thaws every freeze, lifts every filter and removes Tiresias's provider; then freezes nothing more until the service starts again.</summary>
    public AdminThawResult ThawAll()
    {
        lock (gate)
        {
            tornDown = true;
            var state = State();
            var count = state?.Entries.Sum(e => Undo(e.Job, e.Processes.Count)) ?? 0;
            // With the record damaged the filters are still in Tiresias's sublayer, whose removal Windows refuses while any is.
            var lifted = Lift(state?.Entries.SelectMany(e => e.Filters) ?? []) && RemoveProvider();
            if (state is not null && lifted)
            {
                File.Delete(path);
                frozen = AdminFrozen.Empty;
            }
            return new(count);
        }
    }

    /// <summary>How many freezes of the user's are in place.</summary>
    public int Count(string userSid)
    {
        lock (gate)
            return State()?.For(userSid) ?? 0;
    }

    static int Undo(string job, int processes) => ProcessFreezer.Thaw(job) ? processes : 0;

    bool Lift(IEnumerable<ulong> filters)
    {
        try
        {
            return NetworkBlock.Lift(filters);
        }
        catch (Win32Exception e)
        {
            logger.LogError("A frozen program's network block can't be lifted ({Code})", e.NativeErrorCode);
            return false;
        }
    }

    bool RemoveProvider()
    {
        try
        {
            return NetworkBlock.RemoveProvider();
        }
        catch (Win32Exception e)
        {
            logger.LogError("Tiresias's network filtering provider can't be removed ({Code})", e.NativeErrorCode);
            return false;
        }
    }

    AdminFrozen? State()
    {
        if (!loaded)
        {
            try
            {
                frozen = AdminFrozen.Parse(File.Exists(path) ? File.ReadAllText(path) : null);
                // Damaged stays damaged; a file that couldn't be opened is read again next time.
                loaded = true;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                frozen = null;
                logger.LogError("frozen.json can't be opened: {Kind}", e.GetType().Name);
            }
            if (frozen is null)
                logger.LogError("frozen.json can't be read: nothing is frozen until it can");
        }
        return frozen;
    }

    bool Save(AdminFrozen state)
    {
        try
        {
            var temp = path + ".tmp";
            File.WriteAllText(temp, state.ToJson());
            File.Move(temp, path, overwrite: true);
            frozen = state;
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            logger.LogError("frozen.json can't be written: {Kind}", e.GetType().Name);
            return false;
        }
    }

    static FreezeFolders Folders(string userSid)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var profile = UserProfile.Folder(userSid);
        string[] own = profile is null ? [] :
        [
            AdminHandBack.KeyringFolder(profile),
            Path.Combine(profile, "AppData", "Local", "TiresiasApp"),
            Path.Combine(profile, ".dotnet", "tools"),
        ];
        return new(Environment.GetFolderPath(Environment.SpecialFolder.Windows), [Path.Combine(programFiles, "Tiresias"), .. own]);
    }
}

/// <summary>A user's profile folder, from the machine's profile list.</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static class UserProfile
{
    public static string? Folder(string sid)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        return key?.GetValue("ProfileImagePath") is string path ? Environment.ExpandEnvironmentVariables(path) : null;
    }
}
