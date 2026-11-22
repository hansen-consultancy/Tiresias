using System.Security.AccessControl;
using System.Security.Claims;
using System.Security.Principal;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The account facts behind <see cref="Doctor.Reach"/>: which Docker engine pipes exist and whom
/// their DACL grants, which WSL disks the user can read, and how Hyper-V treats their token. Only
/// security descriptors and the registry are read: no pipe is connected to, no disk opened, no
/// distribution started (opening <c>\\wsl.localhost</c> would start one).
/// </summary>
static class ReachProbe
{
    static readonly (string Name, EngineKind Kind)[] EnginePipes =
    [
        ("docker_engine", EngineKind.Current),
        ("dockerDesktopLinuxEngine", EngineKind.Linux),
        ("docker_engine_linux", EngineKind.Linux),
        ("dockerDesktopWindowsEngine", EngineKind.Windows),
        ("docker_engine_windows", EngineKind.Windows),
    ];

    const string HyperVAdministrators = "S-1-5-32-578", Administrators = "S-1-5-32-544";

    public static ReachFacts Read()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var token = Token(identity);
        return new(
            DemoMode.On ? [] : Engines(token),
            Distributions(token),
            DemoMode.On ? HyperVAccess.NotInstalled : HyperV(identity, token));
    }

    /// <summary>The token's enabled SIDs with a name to show: the user as <see cref="Doctor.YourAccount"/>, groups by their name.</summary>
    static Dictionary<string, string> Token(WindowsIdentity identity)
    {
        var token = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [identity.User!.Value] = Doctor.YourAccount };
        // Groups leaves out deny-only SIDs, which grant nothing.
        foreach (var group in identity.Groups ?? [])
            token.TryAdd(group.Value, NameOf(group));
        return token;
    }

    static string NameOf(IdentityReference sid)
    {
        try
        {
            var account = sid.Translate(typeof(NTAccount)).Value;
            return account[(account.IndexOf('\\', StringComparison.Ordinal) + 1)..];
        }
        catch (IdentityNotMappedException)
        {
            return sid.Value;
        }
    }

    static List<EnginePipe> Engines(Dictionary<string, string> token)
    {
        HashSet<string> pipes;
        try
        {
            pipes = new(Directory.GetFiles(@"\\.\pipe\").Select(Path.GetFileName).OfType<string>(), StringComparer.OrdinalIgnoreCase);
        }
        catch (IOException)
        {
            return [];
        }
        return
        [
            .. EnginePipes.Where(p => pipes.Contains(p.Name))
                .Select(p => new EnginePipe(p.Name, p.Kind,
                    Acl(@"\\.\pipe\" + p.Name, directory: false) is { } acl ? ReachAccess.GrantedTo(acl, token, ReachAccess.ReadData | ReachAccess.WriteData) : [])),
        ];
    }

    const string LxssKey = @"Software\Microsoft\Windows\CurrentVersion\Lxss";

    static List<WslDistribution> Distributions(Dictionary<string, string> token)
    {
        using var lxss = UserMachine.CurrentUser.OpenSubKey(LxssKey);
        if (lxss is null)
            return [];
        List<WslDistribution> found = [];
        foreach (var id in lxss.GetSubKeyNames())
        {
            using var key = lxss.OpenSubKey(id);
            if (key?.GetValue("DistributionName") is not string { Length: > 0 } name || key.GetValue("BasePath") is not string { Length: > 0 } basePath)
                continue;
            basePath = basePath.StartsWith(@"\\?\", StringComparison.Ordinal) ? basePath[4..] : basePath;
            var wsl2 = key.GetValue("Version") is int version && version >= 2;
            var disk = wsl2 ? Path.Combine(basePath, key.GetValue("VhdFileName") as string ?? "ext4.vhdx") : Path.Combine(basePath, "rootfs");
            var acl = (wsl2 ? File.Exists(disk) : Directory.Exists(disk)) ? Acl(disk, directory: !wsl2) : null;
            found.Add(new(name, disk, acl is null ? [] : ReachAccess.GrantedTo(acl, token, ReachAccess.ReadData, ownerReads: true)));
        }
        return found;
    }

    static HyperVAccess HyperV(WindowsIdentity identity, Dictionary<string, string> token)
    {
        using (var vmms = UserMachine.LocalMachine?.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\vmms"))
            if (vmms is null)
                return HyperVAccess.NotInstalled;
        if (token.ContainsKey(HyperVAdministrators))
            return HyperVAccess.Member;
        return identity.Claims.Any(c => c.Type == ClaimTypes.DenyOnlySid && c.Value == Administrators)
            ? HyperVAccess.AdminPromptAway
            : HyperVAccess.None;
    }

    /// <summary>The owner and DACL, read with <c>READ_CONTROL</c>; <c>null</c> when even that is refused.</summary>
    static AccessFacts? Acl(string path, bool directory)
    {
        try
        {
            const AccessControlSections sections = AccessControlSections.Access | AccessControlSections.Owner;
            FileSystemSecurity security = directory ? new DirectorySecurity(path, sections) : new FileSecurity(path, sections);
            var owner = security.GetOwner(typeof(SecurityIdentifier))?.Value;
            var entries = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Where(r => (r.PropagationFlags & PropagationFlags.InheritOnly) == 0)
                .Select(r => new AccessEntry(r.IdentityReference.Value, r.AccessControlType == AccessControlType.Allow, (int)r.FileSystemRights));
            return new(owner, [.. entries]);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException or PrivilegeNotHeldException)
        {
            return null;
        }
    }
}
