using System.Text.Json;

namespace Tiresias.Client;

/// <summary>A use of a decoy, from the activity log: the program's path (<c>null</c> when only a pid, or nothing, was known), what it used, and when.</summary>
public sealed record DecoyUseRecord(string? Program, string What, DateTimeOffset At);

/// <summary>Take the program off the blocklist: the user says the decoy use was theirs.</summary>
public sealed record UnblockProgram(string Path) : DoctorFix
{
    public override string Instruction => $"if that was you, unblock {Path} on the Tiresias app's Home; otherwise dismiss this to keep it blocked";
}

public static partial class Doctor
{
    public const string DecoyKind = "programs that used a decoy credential";

    /// <summary>How long a decoy use by a process that couldn't be named stays a finding.</summary>
    public static readonly TimeSpan UnnamedDecoyWindow = TimeSpan.FromDays(30);

    /// <summary>The decoy uses in activity log lines (<c>consumer: decoy</c>); other lines are skipped. The records hold no value.</summary>
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
            if (record is { Consumer: "decoy", Service: { } what })
                yield return new(record.Process is { } process ? ImagePath(process) : null, what, record.Time);
        }
    }

    /// <summary>
    /// A finding per program that used a decoy and is still blocked: the user says whether it was
    /// them (unblock) or not (dismiss, keeping it blocked). Uses whose process couldn't be named
    /// can't be blocked; the last 30 days' are one finding, to be dismissed once looked into.
    /// </summary>
    /// <param name="blocked">The programs on the blocklist.</param>
    public static IEnumerable<DoctorCheck> Decoys(IEnumerable<DecoyUseRecord> uses, IEnumerable<string> blocked, DateTimeOffset now)
    {
        var all = uses.ToArray();
        var blockedPaths = blocked.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var group in all.Where(u => u.Program is not null && blockedPaths.Contains(u.Program)).GroupBy(u => u.Program!, StringComparer.OrdinalIgnoreCase))
        {
            var last = group.MaxBy(u => u.At)!;
            yield return new($"{FileName(group.Key)} used a decoy credential", DoctorStatus.Fail,
                $"{group.Key} connected with {last.What} on {last.At.ToLocalTime():g}{Times(group.Count())}. Nothing legitimate knows that credential, "
                + "so Tiresias blocked the program: no lease, placeholder or consent dialog until you say. Unblock it if that was you",
                new UnblockProgram(group.Key), Kind: DecoyKind, Subject: group.Key);
        }
        // One finding for them all, about the latest: dismissing it holds until the next unnamed use.
        var unnamed = all.Where(u => u.Program is null && now - u.At <= UnnamedDecoyWindow).ToArray();
        if (unnamed.MaxBy(u => u.At) is { } latest)
            yield return new($"A program Tiresias couldn't name used a decoy credential", DoctorStatus.Warn,
                $"Something connected with {latest.What} on {latest.At.ToLocalTime():g}{Times(unnamed.Length)}, and the process was gone or unreadable before it could be named. "
                + "Check the activity log around that time", Kind: DecoyKind, Subject: latest.At.ToString("O"));
    }

    static string Times(int count) => count > 1 ? $" ({count} times in all)" : "";

    sealed record DecoyLine(DateTimeOffset Time, string? Consumer, string? Service, string? Process);
}
