using System.Runtime.InteropServices;
using Microsoft.Win32;
using Tiresias.AdminTier;

namespace Tiresias.Admin;

/// <summary>
/// <c>lastrun</c> (docs/admin-tier.md, <i>Last run</i>): the acting user's Background Activity
/// Moderator key and the machine's Prefetch files, both closed to the user, read for the paths asked
/// and judged by <see cref="AdminLastRun"/>. Only the Prefetch files of programs the user's BAM key
/// lists under a path asked are read; each is kept parsed until it changes.
/// </summary>
sealed partial class LastRunReader
{
    readonly Lock gate = new();
    readonly Dictionary<string, (DateTime Written, PrefetchFile? File)> parsed = new(StringComparer.OrdinalIgnoreCase);

    public AdminLastRuns Read(string userSid, IReadOnlyList<string> asked)
    {
        var devices = Devices();
        var bam = AdminLastRun.Bam(BamValues(userSid), devices)
            .Where(r => asked.Any(a => r.Path.Equals(a.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) || r.Path.StartsWith(a.TrimEnd('\\') + '\\', StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        // Prefetch names a file <EXE>-<hash>.pf, the name cut to 29 characters.
        var names = bam.Select(r => Path.GetFileName(r.Path).ToUpperInvariant()).Select(n => n.Length > 29 ? n[..29] : n).ToHashSet(StringComparer.Ordinal);
        var prefetch = new List<(string, PrefetchFile)>();
        lock (gate)
        {
            foreach (var file in PrefetchFiles())
            {
                var name = Path.GetFileNameWithoutExtension(file);
                var dash = name.LastIndexOf("-", StringComparison.Ordinal);
                if (dash <= 0 || !names.Contains(name[..dash].ToUpperInvariant()) || Parsed(file) is not { } read)
                    continue;
                if (read.ProgramPath is { } device && AdminLastRun.DrivePath(device, devices) is { } path)
                    prefetch.Add((path, read));
            }
        }
        return new(AdminLastRun.Answer(asked, bam, prefetch));
    }

    static IEnumerable<(string, byte[]?)> BamValues(string sid)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{sid}")
            ?? Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\bam\UserSettings\{sid}");
        return key is null ? [] : [.. key.GetValueNames().Select(n => (n, key.GetValue(n) as byte[]))];
    }

    static IEnumerable<string> PrefetchFiles()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        try
        {
            return Directory.Exists(folder) ? Directory.GetFiles(folder, "*.pf") : [];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    PrefetchFile? Parsed(string file)
    {
        try
        {
            var info = new FileInfo(file);
            if (parsed.TryGetValue(file, out var known) && known.Written == info.LastWriteTimeUtc)
                return known.File;
            var read = info.Length is > 0 and <= Prefetch.MaxSize ? Parse(File.ReadAllBytes(file)) : null;
            parsed[file] = (info.LastWriteTimeUtc, read);
            return read;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    static PrefetchFile? Parse(byte[] file)
    {
        if (AdminLastRun.Unwrap(file) is not { } wrapped)
            return null;
        if (!wrapped.Compressed)
            return Prefetch.Parse(file);
        return Decompress(file.AsSpan(wrapped.Offset), wrapped.Size) is { } data ? Prefetch.Parse(data) : null;
    }

    /// <summary>XPRESS Huffman, as Windows compresses Prefetch files since Windows 10.</summary>
    static unsafe byte[]? Decompress(ReadOnlySpan<byte> compressed, int size)
    {
        // RtlDecompressBufferEx's workspace is the fragment size, the second; the larger of the two leaves no doubt.
        if (RtlGetCompressionWorkSpaceSize(XpressHuff, out var bufferWorkspace, out var fragmentWorkspace) != 0)
            return null;
        var workspaceSize = Math.Max(bufferWorkspace, fragmentWorkspace);
        var output = new byte[size];
        var workspace = new byte[workspaceSize];
        fixed (byte* o = output)
        fixed (byte* c = compressed)
        fixed (byte* w = workspace)
            return RtlDecompressBufferEx(XpressHuff, o, (uint)size, c, (uint)compressed.Length, out var final, w) == 0 && final == size ? output : null;
    }

    /// <summary>Each drive's device name and volume serial number, to its letter.</summary>
    static Dictionary<string, string> Devices()
    {
        var devices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buffer = new char[1024];
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable))
        {
            var letter = drive.Name[..2];
            // The device's names, each ended by a NUL: the first is the one paths use.
            if (QueryDosDeviceW(letter, buffer, (uint)buffer.Length) > 0)
                devices.TryAdd(new string(buffer, 0, Math.Max(0, Array.IndexOf(buffer, '\0'))), letter);
            if (GetVolumeInformationW(drive.Name, null, 0, out var serial, out _, out _, null, 0))
                devices.TryAdd(AdminLastRun.VolumeKey(serial), letter);
        }
        return devices;
    }

    const ushort XpressHuff = 4;

    [LibraryImport("ntdll.dll")]
    private static partial int RtlGetCompressionWorkSpaceSize(ushort format, out uint bufferWorkspace, out uint fragmentWorkspace);

    [LibraryImport("ntdll.dll")]
    private static unsafe partial int RtlDecompressBufferEx(ushort format, byte* output, uint outputSize, byte* input, uint inputSize, out uint final, byte* workspace);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint QueryDosDeviceW(string device, [Out] char[] target, uint max);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetVolumeInformationW(string root, [Out] char[]? name, uint nameSize, out uint serial, out uint maxComponent,
        out uint flags, [Out] char[]? fileSystem, uint fileSystemSize);
}
