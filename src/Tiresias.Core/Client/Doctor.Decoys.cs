using System.Text.Json;
using Tiresias.Decoys;

namespace Tiresias.Client;

/// <summary>
/// A use of a decoy, or an open of a decoy file, from the activity log: the program's path (or its
/// file name when only that was known; <c>null</c> when only a pid, or nothing, was), what it did, and when.
/// </summary>
/// <param name="Frozen">The admin tier froze the program for this use and blocked its network.</param>
public sealed record DecoyUseRecord(string? Program, string What, DateTimeOffset At, bool Frozen = false)
{
    /// <summary>An open of a decoy file (layer 2), not a use: it never blocks, and its finding says "opened".</summary>
    public bool IsRead => DecoyReads.IsRead(What);
}

/// <summary>Take the program off the blocklist: the user says the decoy use was theirs.</summary>
public sealed record UnblockProgram(string Path) : DoctorFix
{
    public override string Instruction => $"if that was you, unblock {Path} on the Tiresias app's Home; otherwise dismiss this to keep it blocked";
}

/// <summary>Thaw the program the admin tier froze (UAC), then take it off the blocklist: the user says the decoy use was theirs.</summary>
public sealed record ThawProgram(string Path) : DoctorFix
{
    public override string Instruction => $"if that was you, thaw {Path} on the Tiresias app's Home (an administrator prompt); otherwise dismiss this to keep it frozen and blocked";
}

public static partial class Doctor
{
    /// <summary>Ends a decoy use's activity record when the admin tier froze the program: what the finding reads to offer Thaw.</summary>
    public const string FrozenNote = "frozen, network blocked, by the admin tier";

    public const string DecoyKind = "programs that used a decoy credential";

    public const string DecoyReadKind = "programs that opened a decoy file";

    /// <summary>How long a decoy use by a process that couldn't be named stays a finding.</summary>
    public static readonly TimeSpan UnnamedDecoyWindow = TimeSpan.FromDays(30);

    /// <summary>
    /// The decoy uses and file opens in activity log lines (<c>consumer: decoy</c>); other lines, and
    /// opens by a routine opener (an indexer, antivirus, Explorer, OneDrive), are skipped. The records hold no value.
    /// </summary>
    public static IEnumerable<DecoyUseRecord> DecoyUses(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            DecoyLine? record;
            try
            {
                record = JsonSerializer.Deserialize<DecoyLine>(line, LogJson);
            }
            catch (JsonException)
            {
                continue;
            }
            if (record is { Consumer: "decoy", Service: { } what } && record.Reason?.StartsWith(DecoyReads.RoutineReason, StringComparison.Ordinal) != true)
                yield return new(record.Process is { } process ? ImagePath(process) : null, what, record.Time,
                    record.Reason?.EndsWith(FrozenNote, StringComparison.Ordinal) == true);
        }
    }

    /// <summary>
    /// A finding per program that used a decoy and is still blocked: the user says whether it was
    /// them (unblock) or not (dismiss, keeping it blocked). Uses whose process couldn't be named
    /// can't be blocked; the last 30 days' are one finding, to be dismissed once looked into.
    /// Opens of a decoy file in the last 30 days are warnings, one per program and one for those that
    /// couldn't be named: an open may be harmless, so it blocks nothing and the wording says only "opened".
    /// </summary>
    /// <param name="blocked">The programs on the blocklist.</param>
    public static IEnumerable<DoctorCheck> Decoys(IEnumerable<DecoyUseRecord> uses, IEnumerable<string> blocked, DateTimeOffset now)
    {
        var records = uses.ToArray();
        var all = records.Where(u => !u.IsRead).ToArray();
        var blockedPaths = blocked.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var users = all.Where(u => u.Program is not null && blockedPaths.Contains(u.Program)).GroupBy(u => u.Program!, StringComparer.OrdinalIgnoreCase).ToArray();
        foreach (var group in users)
        {
            var last = group.MaxBy(u => u.At)!;
            // Frozen by any use still listed: thawing undoes every freeze of the program at once.
            var frozen = group.Any(u => u.Frozen);
            yield return new($"{FileName(group.Key)} used a decoy credential", DoctorStatus.Fail,
                $"{group.Key} connected with {last.What} on {last.At.ToLocalTime():g}{Times(group.Count())}. Nothing legitimate knows that credential, "
                + (frozen
                    ? "so Tiresias froze the program and blocked its network, and refuses it any lease, placeholder or consent dialog until you say. Thaw it if that was you"
                    : "so Tiresias blocked the program: no lease, placeholder or consent dialog until you say. Unblock it if that was you"),
                frozen ? new ThawProgram(group.Key) : new UnblockProgram(group.Key), Kind: DecoyKind, Subject: group.Key);
        }
        // One finding for them all, about the latest: dismissing it holds until the next unnamed use.
        var unnamed = all.Where(u => u.Program is null && now - u.At <= UnnamedDecoyWindow).ToArray();
        if (unnamed.MaxBy(u => u.At) is { } latest)
            yield return new($"A program Tiresias couldn't name used a decoy credential", DoctorStatus.Warn,
                $"Something connected with {latest.What} on {latest.At.ToLocalTime():g}{Times(unnamed.Length)}, and the process was gone or unreadable before it could be named. "
                + "Check the activity log around that time", Kind: DecoyKind, Subject: latest.At.ToString("O"));

        // A program blocked for using a decoy is already that finding; its opens add nothing.
        var reads = records.Where(u => u.IsRead && now - u.At <= UnnamedDecoyWindow && !users.Any(g => SamePath(g.Key, u.Program))).ToArray();
        foreach (var group in reads.Where(u => u.Program is not null).GroupBy(u => u.Program!, StringComparer.OrdinalIgnoreCase))
        {
            var last = group.MaxBy(u => u.At)!;
            // Only a full path can be shown in Explorer; a service Tiresias couldn't open is known by its file name.
            yield return new($"{FileName(group.Key)} opened a decoy file", DoctorStatus.Warn,
                $"{group.Key} {last.What} on {last.At.ToLocalTime():g}{Times(group.Count())}. That may be harmless, a backup or search tool, "
                + "or a program looking for credentials; nothing in the file works anywhere, and Tiresias blocked nothing. If you don't know the program, look at where it runs from",
                group.Key.Contains('\\', StringComparison.Ordinal) ? new RevealFile(group.Key) : null, Kind: DecoyReadKind, Subject: $"{group.Key} {last.At:O}");
        }
        var unnamedReads = reads.Where(u => u.Program is null).ToArray();
        if (unnamedReads.MaxBy(u => u.At) is { } latestRead)
            yield return new("A program Tiresias couldn't name opened a decoy file", DoctorStatus.Warn,
                $"Something {latestRead.What} on {latestRead.At.ToLocalTime():g}{Times(unnamedReads.Length)}, and Tiresias couldn't tell which program: "
                + "another woke at the same instant, or it opened the file without waiting. Check the activity log around that time",
                Kind: DecoyReadKind, Subject: latestRead.At.ToString("O"));
    }

    static string Times(int count) => count > 1 ? $" ({count} times in all)" : "";

    sealed record DecoyLine(DateTimeOffset Time, string? Consumer, string? Service, string? Process, string? Reason);
}
