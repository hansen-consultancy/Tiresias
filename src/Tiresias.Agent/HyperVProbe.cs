using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The VM files behind <see cref="Doctor.HyperVContents"/>, only when the user asked: each file's
/// security descriptor, read with <c>READ_CONTROL</c>, never the file. The default folders for
/// everyone; for members of Hyper-V Administrators, also each VM's own paths from read-only WMI
/// queries. Nothing is started, stopped, checkpointed or exported.
/// </summary>
static class HyperVProbe
{
    /// <summary>More files than this are not looked at; the rest are counted.</summary>
    const int MaxFiles = 500;

    static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(10);

    static readonly System.IO.EnumerationOptions Walk = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
        MaxRecursionDepth = 6,
    };

    public static HyperVContents? Read(ReachFacts facts)
    {
        if (facts.HyperV == HyperVAccess.NotInstalled)
            return null;
        using var identity = WindowsIdentity.GetCurrent();
        // Members read everything through the group; the finding is a path that doesn't need it.
        var token = ReachProbe.Token(identity);
        token.Remove(ReachProbe.HyperVAdministrators);

        var vms = facts.HyperV == HyperVAccess.Member ? Vms() : null;
        var known = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, vm) in vms?.Files ?? [])
            known.TryAdd(path, vm);
        string[] folders =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "Hyper-V", "Virtual Hard Disks"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Hyper-V"),
            .. vms?.Folders ?? [],
        ];
        foreach (var folder in folders.Distinct(StringComparer.OrdinalIgnoreCase))
            foreach (var path in Enumerate(folder))
                known.TryAdd(path, null);

        var candidates = known.Where(p => HyperVScan.Kind(p.Key) is not null && Path.IsPathFullyQualified(p.Key)).ToArray();
        var files = candidates.Take(MaxFiles)
            .Where(p => File.Exists(p.Key))
            .Select(p => new HyperVFile(p.Key, HyperVScan.Kind(p.Key)!.Value,
                ReachProbe.Acl(p.Key, directory: false) is { } acl ? ReachAccess.GrantedTo(acl, token, ReachAccess.ReadData, ownerReads: true) : [], p.Value))
            .ToArray();
        return new(vms?.Names, files, Math.Max(0, candidates.Length - MaxFiles));
    }

    static IEnumerable<string> Enumerate(string folder)
    {
        try
        {
            return Directory.Exists(folder) ? Directory.EnumerateFiles(folder, "*", Walk).Take(MaxFiles * 4).ToArray() : [];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    sealed record Machines(IReadOnlyList<string> Names, IReadOnlyList<(string Path, string Vm)> Files, IReadOnlyList<string> Folders);

    /// <summary>
    /// The VMs, their disks and their configuration, checkpoint and saved-state folders, from
    /// <c>root\virtualization\v2</c>; <c>null</c> when WMI doesn't answer.
    /// </summary>
    static Machines? Vms()
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\virtualization\v2", new ConnectionOptions { Timeout = WmiTimeout });
            scope.Connect();
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            // The host is a Msvm_ComputerSystem too, named after the machine; each VM is named by its GUID.
            foreach (var system in Query(scope, "SELECT Name, ElementName FROM Msvm_ComputerSystem"))
                if (system["Name"] is string id && Guid.TryParse(id, out _) && system["ElementName"] is string name)
                    names[id] = name;

            List<string> folders = [];
            foreach (var settings in Query(scope, "SELECT ConfigurationDataRoot, SnapshotDataRoot, SwapFileDataRoot FROM Msvm_VirtualSystemSettingData"))
                foreach (var property in (string[])["ConfigurationDataRoot", "SnapshotDataRoot", "SwapFileDataRoot"])
                    if (settings[property] is string { Length: > 0 } folder && Path.IsPathFullyQualified(folder))
                        folders.Add(folder);

            List<(string, string)> files = [];
            foreach (var disk in Query(scope, "SELECT InstanceID, HostResource FROM Msvm_StorageAllocationSettingData"))
                if (disk["HostResource"] is string[] paths && Owner(disk["InstanceID"] as string, names) is { } vm)
                    files.AddRange(paths.Where(p => p.Length > 0).Select(p => (p, vm)));
            return new([.. names.Values.Order(StringComparer.CurrentCultureIgnoreCase)], files, folders);
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or COMException)
        {
            return null;
        }
    }

    /// <summary>An InstanceID reads <c>Microsoft:&lt;VM GUID&gt;\…</c>.</summary>
    static string? Owner(string? instance, Dictionary<string, string> names)
    {
        if (instance is null || !instance.StartsWith("Microsoft:", StringComparison.OrdinalIgnoreCase))
            return null;
        var id = instance[10..].Split('\\')[0];
        return names.GetValueOrDefault(id);
    }

    static ManagementBaseObject[] Query(ManagementScope scope, string wql)
    {
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql), new System.Management.EnumerationOptions { Timeout = WmiTimeout, ReturnImmediately = true, Rewindable = false });
        using var results = searcher.Get();
        return [.. results.Cast<ManagementBaseObject>()];
    }
}
