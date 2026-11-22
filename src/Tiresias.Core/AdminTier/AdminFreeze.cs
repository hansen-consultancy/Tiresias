using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tiresias.AdminTier;

/// <summary>A running process as the service read it, to decide whether it may be frozen.</summary>
/// <param name="Image">Its full image path; <c>null</c> when it couldn't be read.</param>
/// <param name="OwnerSid">Its token's user; <c>null</c> when it couldn't be read.</param>
/// <param name="Critical">Windows marks it critical: ending or stopping it stops the machine.</param>
public sealed record FreezeCandidate(int ProcessId, int ParentId, DateTime Started, string? Image, string? OwnerSid, bool Critical = false);

/// <summary>A process in a freeze, by id and start time, so a later process under the same id is never taken for it.</summary>
public sealed record FrozenProcess(int ProcessId, DateTime Started, string Image);

/// <summary>Where the programs never frozen live: Windows, and Tiresias's own folders (<c>%ProgramFiles%\Tiresias</c>, the user's <c>%LOCALAPPDATA%\Tiresias</c>).</summary>
public sealed record FreezeFolders(string Windows, IReadOnlyList<string> Tiresias);

/// <summary>What <c>freeze</c> answers: how many processes it froze, and whether the program's network is blocked.</summary>
public sealed record AdminFreezeResult(int Processes, bool NetworkBlocked);

/// <summary>What <c>thaw</c> and <c>teardown</c> answer: how many processes were thawed.</summary>
public sealed record AdminThawResult(int Processes);

/// <summary>
/// Which processes a freeze takes (docs/admin-tier.md, <i>Stopping the program</i>): the process and
/// the ones it started that still run, never a process of another user, a critical one, Windows'
/// shell and session processes, the service or Tiresias itself. A refused descendant is left out; a
/// refused process asked for refuses the freeze. Pure; the service reads the processes.
/// </summary>
public static class AdminFreeze
{
    /// <summary>Processes Windows' sign-in, shell or session can't do without, by file name, only when run from the Windows folder.</summary>
    static readonly string[] WindowsCore =
    [
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
        "logonui.exe", "userinit.exe", "explorer.exe", "dwm.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe", "conhost.exe",
        "taskhostw.exe", "runtimebroker.exe", "audiodg.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
        "searchhost.exe", "textinputhost.exe",
    ];

    static readonly string[] OwnImages = ["tir.exe", "tiresias.exe", "tiresias-admin.exe"];

    /// <summary><see cref="Plan"/>'s refusal when every process it would take is frozen already: no failure, the work is done.</summary>
    public const string AlreadyFrozen = "is frozen already";

    /// <summary>How deep under the process asked for its descendants are looked for.</summary>
    const int MaxDepth = 16;

    /// <summary>Why <paramref name="process"/> may not be frozen for <paramref name="userSid"/>; <c>null</c> when it may.</summary>
    public static string? Refusal(FreezeCandidate process, string userSid, int servicePid, FreezeFolders folders)
    {
        if (process.ProcessId is 0 or 4)
            return "is the system";
        if (process.ProcessId == servicePid)
            return "is the admin tier itself";
        if (process.OwnerSid is null || process.Image is null)
            return "can't be read";
        if (!string.Equals(process.OwnerSid, userSid, StringComparison.OrdinalIgnoreCase))
            return "isn't the user's";
        if (process.Critical)
            return "is critical to Windows";
        var name = FileName(process.Image);
        if (Under(process.Image, folders.Windows) && WindowsCore.Contains(name, StringComparer.OrdinalIgnoreCase))
            return "is part of Windows' session";
        if (folders.Tiresias.Any(f => Under(process.Image, f)) && OwnImages.Contains(name, StringComparer.OrdinalIgnoreCase))
            return "is Tiresias";
        return null;
    }

    /// <summary>
    /// The processes to freeze: <paramref name="root"/> and its still-running descendants, each
    /// started after its parent (a parent id is only a number, reused once the parent exits), minus
    /// the refused and the already frozen.
    /// </summary>
    /// <returns>The processes, root first; or why the root itself can't be.</returns>
    public static (IReadOnlyList<FrozenProcess> Processes, string? Refusal) Plan(int root, IReadOnlyList<FreezeCandidate> running, string userSid,
        int servicePid, FreezeFolders folders, IReadOnlyCollection<FrozenProcess> alreadyFrozen)
    {
        if (running.FirstOrDefault(p => p.ProcessId == root) is not { } first)
            return ([], "isn't running");
        if (Refusal(first, userSid, servicePid, folders) is { } refusal)
            return ([], refusal);
        var taken = new List<FreezeCandidate> { first };
        var level = new List<FreezeCandidate> { first };
        for (var depth = 0; depth < MaxDepth && level.Count > 0; depth++)
        {
            level = [.. running.Where(child => level.Any(parent => child.ParentId == parent.ProcessId && child.Started >= parent.Started)
                && !taken.Any(t => t.ProcessId == child.ProcessId))];
            taken.AddRange(level);
        }
        var processes = taken
            .Where(p => p == first || Refusal(p, userSid, servicePid, folders) is null)
            .Select(p => new FrozenProcess(p.ProcessId, p.Started, p.Image!))
            .Where(p => !alreadyFrozen.Contains(p))
            .ToArray();
        return processes.Length == 0 ? ([], AlreadyFrozen) : (processes, null);
    }

    /// <summary>
    /// A freeze's job object: named, so the service finds it again after a restart, and an elevated
    /// removal without the service; unguessable, since any user may create a job under a
    /// <c>Global\</c> name first.
    /// </summary>
    public static string JobName(Guid id) => $@"Global\Tiresias.Freeze.{id:N}";

    static bool Under(string path, string root) =>
        root.Length > 0 && path.StartsWith(root.TrimEnd('\\') + '\\', StringComparison.OrdinalIgnoreCase);

    /// <summary>Windows paths on any OS: the tests run on Linux too.</summary>
    static string FileName(string path) => path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
}

/// <summary>One freeze: whose, which program, its job, the processes in it and the network filters it holds.</summary>
/// <param name="Job">The job object's name (<see cref="AdminFreeze.JobName"/>).</param>
/// <param name="Filters">The Windows Filtering Platform filter ids blocking the program; none when another freeze of it already holds them.</param>
public sealed record AdminFreezeEntry(long Id, string UserSid, string Program, string Job, IReadOnlyList<FrozenProcess> Processes,
    IReadOnlyList<ulong> Filters, DateTimeOffset At);

/// <summary>
/// The freezes in place (<c>frozen.json</c> in the service's state folder), kept so a restart can
/// still thaw them and lift their filters, and so removal can when the service doesn't answer.
/// Immutable.
/// </summary>
public sealed record AdminFrozen(long NextId, IReadOnlyList<AdminFreezeEntry> Entries)
{
    public const int Version = 1;

    public static readonly AdminFrozen Empty = new(1, []);

    /// <summary>Records a freeze made under <see cref="NextId"/>.</summary>
    public AdminFrozen Add(AdminFreezeEntry entry) => new(Math.Max(NextId, entry.Id + 1), [.. Entries, entry]);

    /// <summary>Every process frozen now, so none is frozen twice.</summary>
    public IReadOnlyCollection<FrozenProcess> Processes => [.. Entries.SelectMany(e => e.Processes)];

    /// <summary>Whether a filter already blocks the program, so a second freeze of it adds none.</summary>
    public bool Blocked(string program) => Entries.Any(e => e.Filters.Count > 0 && SamePath(e.Program, program));

    /// <summary>
    /// The user's freezes of <paramref name="program"/>, taken out: <c>thaw</c> thaws each job and
    /// lifts <c>Lift</c>. Filters still needed by another user's freeze of the same program (they
    /// block the program, whoever runs it) pass to that freeze instead of being lifted.
    /// </summary>
    public (IReadOnlyList<AdminFreezeEntry> Thawed, IReadOnlyList<ulong> Lift, AdminFrozen Left) Thaw(string userSid, string program)
    {
        var thawed = Entries.Where(e => string.Equals(e.UserSid, userSid, StringComparison.OrdinalIgnoreCase) && SamePath(e.Program, program)).ToArray();
        var filters = thawed.SelectMany(e => e.Filters).ToArray();
        var left = Entries.Except(thawed).ToList();
        var heir = left.FindIndex(e => SamePath(e.Program, program));
        if (heir < 0 || filters.Length == 0)
            return (thawed, filters, this with { Entries = left });
        left[heir] = left[heir] with { Filters = [.. left[heir].Filters, .. filters] };
        return (thawed, [], this with { Entries = left });
    }

    public int For(string userSid) => Entries.Count(e => string.Equals(e.UserSid, userSid, StringComparison.OrdinalIgnoreCase));

    static bool SamePath(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(new File(Version, NextId, [.. Entries]), Json);

    /// <returns>
    /// <see cref="Empty"/> for no file. A damaged one, or a newer one, is <c>null</c>: the service
    /// then refuses to freeze rather than lose track of freezes it can no longer thaw.
    /// </returns>
    public static AdminFrozen? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Empty;
        try
        {
            return JsonSerializer.Deserialize<File>(json, Json) is { V: Version, NextId: > 0, Entries: { } entries } file
                && entries.All(e => e is { UserSid: not null, Program: not null, Job: not null, Processes: not null, Filters: not null } && e.Id < file.NextId)
                ? new(file.NextId, entries)
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    sealed record File(int V, long NextId, AdminFreezeEntry[]? Entries);
}

public static partial class AdminArgs
{
    /// <summary><c>freeze</c>'s <c>pid</c>: a process id, never the idle or system process.</summary>
    public static bool Pid(JsonNode? node) => Int(node, 8, int.MaxValue, out _);
}
