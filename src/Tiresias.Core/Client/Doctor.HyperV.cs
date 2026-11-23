namespace Tiresias.Client;

/// <summary>What a Hyper-V file gives whoever copies it.</summary>
public enum HyperVFileKind
{
    /// <summary><c>.vhdx</c>, <c>.vhd</c>: the guest's file system.</summary>
    Disk,
    /// <summary><c>.avhdx</c>, <c>.avhd</c>: a checkpoint's differencing disk.</summary>
    Checkpoint,
    /// <summary><c>.vmrs</c>, <c>.vmgs</c>, <c>.bin</c>, <c>.vsv</c>: saved state, which holds the guest's memory.</summary>
    Memory,
}

/// <summary>A VM file and whom of the user's token, Hyper-V Administrators aside, its DACL lets read it. Never opened.</summary>
/// <param name="Vm">The VM WMI says it belongs to; <c>null</c> when it was found by folder.</param>
public sealed record HyperVFile(string Path, HyperVFileKind Kind, IReadOnlyList<string> ReadableFor, string? Vm = null);

/// <summary>The VM files looked at, from the default folders and, for members, the VMs' own paths.</summary>
/// <param name="Vms">The VMs' names from WMI; <c>null</c> when the user isn't in Hyper-V Administrators or WMI didn't answer.</param>
/// <param name="LeftOut">Files past the first ones, not looked at.</param>
public sealed record HyperVContents(IReadOnlyList<string>? Vms, IReadOnlyList<HyperVFile> Files, int LeftOut = 0);

public static class HyperVScan
{
    /// <summary>What a file is by its extension; <c>null</c> for a configuration file or anything else, which hold no guest data.</summary>
    public static HyperVFileKind? Kind(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".vhdx" or ".vhd" => HyperVFileKind.Disk,
        ".avhdx" or ".avhd" => HyperVFileKind.Checkpoint,
        ".vmrs" or ".vmgs" or ".bin" or ".vsv" => HyperVFileKind.Memory,
        _ => null,
    };
}

public static partial class Doctor
{
    public const string HyperVContentsCheck = "hyper-v files";

    /// <summary>
    /// Which VM disks, checkpoints and saved states the user's token can read without Hyper-V
    /// Administrators, when the user asked to look: a copy of one is the guest's files or memory,
    /// offline. Members also see which VMs the group opens. Not asked, one passing line says how.
    /// </summary>
    public static IEnumerable<DoctorCheck> HyperVContents(ReachFacts facts, ReachContents? contents)
    {
        if (facts.HyperV == HyperVAccess.NotInstalled)
            yield break;
        if (contents?.HyperV is not { } hyperV)
        {
            yield return new(HyperVContentsCheck, DoctorStatus.Ok,
                "not looked at: tir doctor --reach, or Check now on Home, checks which VM disks, checkpoints and saved states your account can read, without opening them");
            yield break;
        }

        var readable = hyperV.Files.Where(f => f.ReadableFor.Count > 0).ToArray();
        foreach (var file in readable)
            yield return new($"hyper-v file {WindowsFileName(file.Path)}", DoctorStatus.Warn,
                $"{file.Path}, {Describe(file)}, is readable for {string.Join(" and ", file.ReadableFor)}: any program you run can copy it and read {(file.Kind == HyperVFileKind.Memory ? "the guest's memory" : "the guest's files")} offline, without Hyper-V",
                new ReachGuide(ReachTopic.HyperVFiles), Kind: "Hyper-V files readable without the group");

        var vms = hyperV.Vms is { Count: > 0 } names ? $"; Hyper-V Administrators opens {names.Count} {(names.Count == 1 ? "VM" : "VMs")}: {string.Join(", ", names)}" : "";
        var leftOut = hyperV.LeftOut == 0 ? "" : $"; {hyperV.LeftOut} more were not looked at";
        if (readable.Length == 0)
            yield return new(HyperVContentsCheck, DoctorStatus.Ok,
                $"looked at {hyperV.Files.Count} VM {(hyperV.Files.Count == 1 ? "file" : "files")}: none readable without Hyper-V Administrators{vms}{leftOut}");
        else if (vms.Length > 0 || leftOut.Length > 0)
            yield return new(HyperVContentsCheck, DoctorStatus.Ok, $"looked at {hyperV.Files.Count} VM files{vms}{leftOut}");
    }

    /// <summary>A Windows path's last segment on any OS: <see cref="Path.GetFileName(string)"/> splits on <c>/</c> only off Windows.</summary>
    static string WindowsFileName(string path) => path[(path.LastIndexOfAny(['\\', '/']) + 1)..];

    static string Describe(HyperVFile file) => file.Kind switch
    {
        HyperVFileKind.Disk => "a VM disk",
        HyperVFileKind.Checkpoint => "a checkpoint disk",
        _ => "a saved state",
    } + (file.Vm is { } vm ? $" of {vm}" : "");
}
