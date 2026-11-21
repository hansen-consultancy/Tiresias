namespace Tiresias.Decoys;

/// <summary>Where routine openers run from on this machine (<c>%WINDIR%</c>, <c>%ProgramFiles%</c> and so on), and Tiresias's own folder.</summary>
public sealed record RoutineFolders(string Windows, IReadOnlyList<string> ProgramFiles, string ProgramData, string? Tiresias);

/// <summary>
/// The words and rules of a decoy file being opened (layer 2). An open is a fact that may be
/// harmless (principle 5), so it says "opened", never more, and a known indexer, antivirus, shell
/// or sync client opening it is recorded but raises nothing.
/// </summary>
public static class DecoyReads
{
    /// <summary>Starts every read's <c>What</c>; how the activity log tells a read from a use.</summary>
    public const string Opened = "opened the decoy file ";

    /// <summary>Starts the activity record's reason for a routine opener, which the doctor then skips.</summary>
    public const string RoutineReason = "Routine opener";

    /// <summary>What happened, as the activity log, the notification and the finding say it.</summary>
    public static string What(string file) => Opened + FileName(file);

    public static bool IsRead(string what) => what.StartsWith(Opened, StringComparison.Ordinal);

    sealed record Routine(string Label, string[] Images, Func<RoutineFolders, IEnumerable<string>> Roots);

    static readonly Routine[] Routines =
    [
        new("Windows Search", ["SearchProtocolHost.exe", "SearchIndexer.exe", "SearchFilterHost.exe"], f => [f.Windows]),
        new("Microsoft Defender", ["MsMpEng.exe", "MpDefenderCoreService.exe"],
            f => [.. f.ProgramFiles, Below(f.ProgramData, @"Microsoft\Windows Defender")]),
        new("Microsoft Defender for Endpoint", ["MsSense.exe"],
            f => [.. f.ProgramFiles, Below(f.ProgramData, @"Microsoft\Windows Defender Advanced Threat Protection")]),
        new("File Explorer", ["explorer.exe", "prevhost.exe"], f => [f.Windows]),
        new("OneDrive", ["OneDrive.exe", "OneDrive.Sync.Service.exe"],
            // Only the machine-wide install: a per-user one runs from a folder any program the user runs can write to.
            f => [.. f.ProgramFiles]),
    ];

    /// <summary>
    /// What a routine opener is ("Windows Search"), or <c>null</c> when it isn't one. Both the image's
    /// file name and where it runs from must match: a program named <c>explorer.exe</c> in Downloads
    /// is not Explorer. An opener known only by its file name (its path couldn't be read) is not routine.
    /// </summary>
    /// <param name="image">The opener's full image path.</param>
    public static string? RoutineOpener(string? image, RoutineFolders folders)
    {
        if (string.IsNullOrEmpty(image) || !image.Contains('\\', StringComparison.Ordinal) || image.Contains(@"\..\", StringComparison.Ordinal))
            return null;
        var name = FileName(image);
        // Only Tiresias's own programs: its folder may be the user's to write to, so nothing else there is vouched for.
        if (folders.Tiresias is { Length: > 0 } own && Under(image, own) && OwnImages.Contains(name, StringComparer.OrdinalIgnoreCase))
            return "Tiresias";
        return Routines.FirstOrDefault(r => r.Images.Contains(name, StringComparer.OrdinalIgnoreCase) && r.Roots(folders).Any(root => Under(image, root)))?.Label;
    }

    static readonly string[] OwnImages = ["tir.exe", "Tiresias.exe"];

    static string Below(string root, string relative) => root.Length == 0 ? "" : $@"{root.TrimEnd('\\')}\{relative}";

    static bool Under(string path, string root) =>
        root.Length > 0 && path.StartsWith(root.TrimEnd('\\') + '\\', StringComparison.OrdinalIgnoreCase);

    /// <summary>Windows paths on any OS: the tests run on Linux too.</summary>
    static string FileName(string path) => path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
}
