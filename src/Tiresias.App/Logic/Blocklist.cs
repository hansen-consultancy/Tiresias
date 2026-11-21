using System.Text.Json;

namespace Tiresias.App.Logic;

/// <summary>A program the user said "This wasn't me" about: its path and, when it could be read, the SHA-256 of the file (hex).</summary>
public sealed record BlockedProgram(string Path, string? Sha256, DateTimeOffset Since);

/// <summary>What the gate does with a request before any dialog is shown.</summary>
public enum GateDecision
{
    /// <summary>Show the consent dialog as usual.</summary>
    Ask,
    /// <summary>Refuse without asking: "This wasn't me" was chosen and nobody has unlocked with Windows Hello since.</summary>
    LockedDown,
    /// <summary>Refuse without asking: the program is on the blocklist.</summary>
    Blocked,
}

/// <summary>
/// The "This wasn't me" state: a lockdown that refuses every request until the user unlocks with
/// Windows Hello from the app itself, and the programs refused for good until the user unblocks
/// them. Immutable; the app keeps one, saves it after each change, and asks it about every request.
/// </summary>
public sealed record Blocklist(bool LockedDown, IReadOnlyList<BlockedProgram> Programs)
{
    /// <summary>The file format; a change bumps it, and a newer file is read as a lockdown rather than ignored.</summary>
    public const int Version = 1;

    public static readonly Blocklist Empty = new(false, []);

    /// <summary>
    /// A program matches by path, or by file content wherever it now lives: a copy or a rename of a
    /// blocked file is still blocked. <paramref name="hash"/> is called only when a blocked program
    /// has a hash and the path didn't match already, so an empty list costs no file read.
    /// </summary>
    /// <param name="program">The image path of the program asking, or <c>null</c> when unknown.</param>
    /// <param name="hash">The SHA-256 of a file, or <c>null</c> when it can't be read.</param>
    public GateDecision Decide(string? program, Func<string, string?> hash)
    {
        if (LockedDown)
            return GateDecision.LockedDown;
        if (program is null || Programs.Count == 0)
            return GateDecision.Ask;
        if (Programs.Any(p => SamePath(p.Path, program)))
            return GateDecision.Blocked;
        if (!Programs.Any(p => p.Sha256 is not null))
            return GateDecision.Ask;
        return hash(program) is { } sha && Programs.Any(p => string.Equals(p.Sha256, sha, StringComparison.OrdinalIgnoreCase))
            ? GateDecision.Blocked
            : GateDecision.Ask;
    }

    /// <summary>
    /// "This wasn't me": lock down, and block the program when it names a file. A program the agent
    /// only knows as <c>pid N</c> (or not at all) can't be blocked; the lockdown still holds.
    /// </summary>
    public Blocklist Escalate(string? program, string? sha256, DateTimeOffset now)
    {
        if (program is null || !IsWindowsPath(program))
            return this with { LockedDown = true };
        var others = Programs.Where(p => !SamePath(p.Path, program));
        return new(true, [.. others, new BlockedProgram(program, sha256, now)]);
    }

    /// <summary>
    /// A decoy credential was used: block the program without a lockdown, since nothing was asked
    /// of the user and their other programs are not in doubt. A program known only by its pid can't
    /// be blocked, and the list stays as it is.
    /// </summary>
    public Blocklist Block(string? program, string? sha256, DateTimeOffset now) =>
        program is null || !IsWindowsPath(program) || Programs.Any(p => SamePath(p.Path, program))
            ? this
            : this with { Programs = [.. Programs, new BlockedProgram(program, sha256, now)] };

    /// <summary>The user unlocked with Windows Hello from the app: requests are asked about again, blocked programs stay blocked.</summary>
    public Blocklist Unlocked() => this with { LockedDown = false };

    public Blocklist Unblock(string path) => this with { Programs = [.. Programs.Where(p => !SamePath(p.Path, path))] };

    /// <summary>A full Windows path (<c>C:\…</c> or <c>\\server\…</c>), judged the same on any OS so the tests run on Linux too.</summary>
    static bool IsWindowsPath(string path) =>
        (path is [var drive, ':', '\\' or '/', ..] && char.IsAsciiLetter(drive)) || path.StartsWith(@"\\", StringComparison.Ordinal);

    static bool SamePath(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public string ToJson() => JsonSerializer.Serialize(new File(Version, LockedDown, [.. Programs]), Json);

    /// <summary>
    /// <c>null</c> (no file) is an empty list. A damaged file, or one from a newer app, fails closed:
    /// locked down, so the next Windows Hello unlock from the app is the way out, and nothing is
    /// silently unblocked by a file that could not be read.
    /// </summary>
    public static Blocklist Parse(string? json)
    {
        if (json is null)
            return Empty;
        try
        {
            var file = JsonSerializer.Deserialize<File>(json, Json);
            if (file is null || file.V != Version)
                return new(true, []);
            return new(file.LockedDown, [.. (file.Programs ?? []).Where(p => !string.IsNullOrEmpty(p.Path))]);
        }
        catch (JsonException)
        {
            return new(true, []);
        }
    }

    sealed record File(int V, bool LockedDown, BlockedProgram[]? Programs);
}
