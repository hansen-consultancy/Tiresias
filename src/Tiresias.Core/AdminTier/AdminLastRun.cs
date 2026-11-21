using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Tiresias.AdminTier;

/// <summary>One program's runs, as <c>lastrun</c> answers them.</summary>
/// <param name="Path">The program's drive path, as Windows recorded it (Prefetch's in capitals).</param>
/// <param name="LastRun">When it last ran for the acting user (the Background Activity Moderator), or Prefetch's latest run when later.</param>
/// <param name="Runs">How often it ran, from Prefetch; 0 when Prefetch has no file for it.</param>
/// <param name="Recent">Prefetch's last run times, newest first, at most 8.</param>
public sealed record AdminProgramRun(string Path, DateTimeOffset LastRun, int Runs = 0, IReadOnlyList<DateTimeOffset>? Recent = null);

/// <summary>What <c>lastrun</c> answers.</summary>
public sealed record AdminLastRuns(IReadOnlyList<AdminProgramRun> Runs);

/// <summary>A program run the Background Activity Moderator recorded for a user, its path a drive path.</summary>
public sealed record BamRun(string Path, DateTimeOffset LastRun);

/// <summary>A Prefetch file's facts: the program's name, the files it loaded (device paths), how often and when it last ran.</summary>
public sealed record PrefetchFile(string Executable, IReadOnlyList<string> Files, int RunCount, IReadOnlyList<DateTimeOffset> LastRuns)
{
    /// <summary>
    /// The program's own path among the files it loaded: the one whose name is the executable's.
    /// The name field holds at most 29 characters, so a longer name matches on its start.
    /// </summary>
    public string? ProgramPath => Files.FirstOrDefault(f =>
    {
        var name = f[(f.LastIndexOf('\\') + 1)..];
        return Executable.Length >= 29 ? name.StartsWith(Executable, StringComparison.OrdinalIgnoreCase) : name.Equals(Executable, StringComparison.OrdinalIgnoreCase);
    });
}

/// <summary>
/// <c>lastrun</c> (docs/admin-tier.md, <i>Last run</i>): reads of the Background Activity Moderator
/// and Prefetch, both readable only by an administrator, answered only for the paths asked and only
/// for the acting user. Pure: the service reads the registry and the files and maps the volumes.
/// </summary>
public static class AdminLastRun
{
    /// <summary>Most programs one answer holds: a folder asked for can match many.</summary>
    public const int MaxRuns = 1024;

    /// <summary>
    /// The runs to answer: each asked path's own, or, for a folder, those of the programs under it.
    /// Only programs the user's own BAM lists: Prefetch is the machine's, every user's runs together,
    /// so its count and times are added only to a program this user is known to have run.
    /// </summary>
    public static IReadOnlyList<AdminProgramRun> Answer(IReadOnlyList<string> asked, IEnumerable<BamRun> bam, IEnumerable<(string Path, PrefetchFile File)> prefetch)
    {
        var prefetched = prefetch.GroupBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(p => p.File).ToArray(), StringComparer.OrdinalIgnoreCase);
        var runs = new List<AdminProgramRun>();
        foreach (var run in bam.GroupBy(r => r.Path, StringComparer.OrdinalIgnoreCase).Select(g => g.MaxBy(r => r.LastRun)!))
        {
            if (!asked.Any(a => SameOrUnder(run.Path, a)))
                continue;
            var files = prefetched.GetValueOrDefault(run.Path) ?? [];
            var recent = files.SelectMany(f => f.LastRuns).OrderDescending().Take(8).ToArray();
            var last = recent.Length > 0 && recent[0] > run.LastRun ? recent[0] : run.LastRun;
            runs.Add(new(run.Path, last, files.Sum(f => f.RunCount), recent));
            if (runs.Count == MaxRuns)
                break;
        }
        return runs;
    }

    static bool SameOrUnder(string path, string asked)
    {
        var folder = asked.TrimEnd('\\');
        return path.Equals(folder, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(folder + '\\', StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The values of a user's BAM key (<c>...\bam\State\UserSettings\&lt;sid&gt;</c>): a program's
    /// device path, its data starting with the last run as a FILETIME. Other values (<c>Version</c>,
    /// <c>SequenceNumber</c>, packaged apps) and paths on a volume not mapped are skipped.
    /// </summary>
    public static IEnumerable<BamRun> Bam(IEnumerable<(string Name, byte[]? Data)> values, IReadOnlyDictionary<string, string> devices)
    {
        foreach (var (name, data) in values)
        {
            if (data is not { Length: >= 8 } || DrivePath(name, devices) is not { } path || FileTime(data) is not { } at)
                continue;
            yield return new(path, at);
        }
    }

    /// <summary>
    /// A device path as a drive path: <c>\Device\HarddiskVolume3\x</c> by the device's name, and
    /// Prefetch's <c>\VOLUME{&lt;created&gt;-&lt;serial&gt;}\x</c> by the volume's serial number, keyed
    /// <c>VOLUME:&lt;serial in hex&gt;</c>. <c>null</c> when the volume isn't one of <paramref name="devices"/>.
    /// </summary>
    /// <param name="devices">Device names and <c>VOLUME:</c> serials, to drive letters (<c>C:</c>).</param>
    public static string? DrivePath(string path, IReadOnlyDictionary<string, string> devices)
    {
        if (path.StartsWith(@"\VOLUME{", StringComparison.OrdinalIgnoreCase))
        {
            var close = path.IndexOf('}', StringComparison.Ordinal);
            var dash = close > 0 ? path.LastIndexOf('-', close) : -1;
            if (dash < 0 || close + 1 >= path.Length || path[close + 1] != '\\')
                return null;
            return devices.TryGetValue("VOLUME:" + path[(dash + 1)..close].ToUpperInvariant(), out var drive) ? drive + path[(close + 1)..] : null;
        }
        // \Device\HarddiskVolume3\...: the device is the first two segments.
        var second = path.Length > 1 ? path.IndexOf('\\', path.IndexOf('\\', 1) + 1) : -1;
        if (!path.StartsWith('\\') || second < 0)
            return null;
        return devices.TryGetValue(path[..second], out var letter) ? letter + path[second..] : null;
    }

    /// <summary>The key <see cref="DrivePath"/> looks a volume up by, from its serial number.</summary>
    public static string VolumeKey(uint serial) => "VOLUME:" + serial.ToString("X8", CultureInfo.InvariantCulture);

    static DateTimeOffset? FileTime(ReadOnlySpan<byte> data)
    {
        var value = BinaryPrimitives.ReadInt64LittleEndian(data);
        return value > 0 && value < DateTime.MaxValue.ToFileTimeUtc() ? new DateTimeOffset(DateTime.FromFileTimeUtc(value)) : null;
    }

    /// <summary>
    /// Where a Prefetch file's SCCA data is: the whole file when uncompressed; for a <c>MAM</c> file,
    /// the XPRESS Huffman data after its header, and the size it decompresses to.
    /// </summary>
    /// <returns><c>null</c> for neither, or a size past <see cref="Prefetch.MaxSize"/>.</returns>
    public static (bool Compressed, int Offset, int Size)? Unwrap(ReadOnlySpan<byte> file)
    {
        if (file.Length >= 8 && file[4..8].SequenceEqual("SCCA"u8))
            return (false, 0, file.Length);
        if (file.Length < 8 || file[0] != 'M' || file[1] != 'A' || file[2] != 'M' || (file[3] & 0x7F) != 4)
            return null;
        var size = BinaryPrimitives.ReadUInt32LittleEndian(file[4..]);
        // With the high bit set, a CRC32 follows the size.
        var offset = (file[3] & 0x80) != 0 ? 12 : 8;
        return size is > 0 and <= Prefetch.MaxSize && file.Length > offset ? (true, offset, (int)size) : null;
    }
}

/// <summary>
/// Reads a decompressed Prefetch file (versions 30 and 31, Windows 10 and 11), checking every
/// offset and size against the data: a damaged or crafted file reads as <c>null</c>, never throws.
/// </summary>
public static class Prefetch
{
    public const int MaxSize = 16 * 1024 * 1024;

    /// <summary>Most file names read from one Prefetch file.</summary>
    const int MaxFiles = 4096;

    const int Header = 84;
    const int LastRunsAt = 128;

    public static PrefetchFile? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 216 || data.Length > MaxSize || !data[4..8].SequenceEqual("SCCA"u8))
            return null;
        var version = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (version is not (30 or 31))
            return null;
        var executable = Utf16Z(data.Slice(16, 60));
        var metrics = U32(data, Header);
        var namesAt = U32(data, Header + 16);
        var namesSize = U32(data, Header + 20);
        if (executable.Length == 0 || (ulong)namesAt + namesSize > (ulong)data.Length || namesAt < 216 && namesSize > 0)
            return null;
        // Two layouts of version 30: the file information is 8 bytes shorter when the metrics start at 0x128, and the count with it.
        var count = U32(data, metrics == 0x128 ? 200 : 208);
        var lastRuns = new List<DateTimeOffset>();
        for (var i = 0; i < 8; i++)
        {
            var value = BinaryPrimitives.ReadInt64LittleEndian(data[(LastRunsAt + i * 8)..]);
            if (value > 0 && value < DateTime.MaxValue.ToFileTimeUtc())
                lastRuns.Add(new DateTimeOffset(DateTime.FromFileTimeUtc(value)));
        }
        var files = Utf16List(data.Slice((int)namesAt, (int)namesSize));
        return new(executable, files, count > int.MaxValue ? 0 : (int)count, lastRuns);
    }

    static uint U32(ReadOnlySpan<byte> data, int at) => BinaryPrimitives.ReadUInt32LittleEndian(data[at..]);

    static string Utf16Z(ReadOnlySpan<byte> bytes)
    {
        var text = Encoding.Unicode.GetString(bytes[..(bytes.Length & ~1)]);
        var end = text.IndexOf('\0', StringComparison.Ordinal);
        return end < 0 ? text : text[..end];
    }

    static IReadOnlyList<string> Utf16List(ReadOnlySpan<byte> bytes) =>
        [.. Encoding.Unicode.GetString(bytes[..(bytes.Length & ~1)]).Split('\0', StringSplitOptions.RemoveEmptyEntries).Take(MaxFiles)];
}

public static partial class AdminArgs
{
    public const int MaxRunPaths = 256;

    /// <summary><c>lastrun</c>'s <c>paths</c>: programs or folders, by drive-rooted path, a few hundred at most.</summary>
    public static bool RunPaths(JsonNode? node) =>
        node is JsonArray paths && paths.Count is > 0 and <= MaxRunPaths && paths.All(p => Text(p, MaxPath) && FullPath((string)p!));
}
