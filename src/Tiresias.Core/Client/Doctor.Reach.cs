namespace Tiresias.Client;

/// <summary>Which engine a Docker pipe serves: the Windows-containers engine runs as SYSTEM, so its pipe is administrator on the host.</summary>
public enum EngineKind { Linux, Windows, Current }

/// <summary>A Docker engine pipe that exists, and which of the user's token SIDs its DACL grants read and write; empty when none.</summary>
public sealed record EnginePipe(string Name, EngineKind Kind, IReadOnlyList<string> GrantedTo);

/// <summary>A WSL distribution's disk (WSL 2's <c>ext4.vhdx</c>, WSL 1's <c>rootfs</c> folder) and whom of the user's token it is readable for.</summary>
public sealed record WslDistribution(string Name, string Disk, IReadOnlyList<string> ReadableFor);

public enum HyperVAccess
{
    NotInstalled,
    /// <summary>Hyper-V is installed and the user's token can't manage it.</summary>
    None,
    /// <summary>Hyper-V Administrators is enabled in the token: UAC doesn't filter it.</summary>
    Member,
    /// <summary>Only through Administrators, which is deny-only until a UAC prompt.</summary>
    AdminPromptAway,
}

/// <summary>
/// What the user's own account can open without admin rights: Docker engine pipes, WSL disks,
/// Hyper-V (docs/containers-and-vms.md, phase 1). Account facts only: nothing inside is read.
/// </summary>
public sealed record ReachFacts(IReadOnlyList<EnginePipe> Engines, IReadOnlyList<WslDistribution> Distributions, HyperVAccess HyperV)
{
    public static readonly ReachFacts None = new([], [], HyperVAccess.NotInstalled);
}

/// <summary>One access control entry, by SID; <paramref name="Rights"/> as Windows stores it (generic bits allowed).</summary>
public sealed record AccessEntry(string Sid, bool Allow, int Rights);

/// <summary>A file's or pipe's owner and DACL, read with <c>READ_CONTROL</c> only.</summary>
public sealed record AccessFacts(string? Owner, IReadOnlyList<AccessEntry> Entries);

/// <summary>Whether a security descriptor lets a token in, from the descriptor and the token's enabled SIDs: a pure stand-in for <c>AccessCheck</c>.</summary>
public static class ReachAccess
{
    public const int ReadData = 0x1, WriteData = 0x2;
    const int GenericRead = unchecked((int)0x80000000), GenericWrite = 0x40000000, GenericAll = 0x10000000;

    /// <summary>The token's names the descriptor grants <paramref name="rights"/> through, or empty when it doesn't (a matching deny wins).</summary>
    /// <param name="token">The token's enabled SIDs (user and groups, never deny-only ones) with the name to show for each.</param>
    /// <param name="ownerReads">Count ownership as access: an owner can rewrite the DACL to give itself any right.</param>
    public static IReadOnlyList<string> GrantedTo(AccessFacts acl, IReadOnlyDictionary<string, string> token, int rights, bool ownerReads = false)
    {
        var mine = acl.Entries.Where(e => token.ContainsKey(e.Sid)).ToArray();
        var denied = mine.Where(e => !e.Allow).Aggregate(0, (r, e) => r | Map(e.Rights));
        var allowed = mine.Where(e => e.Allow).Aggregate(0, (r, e) => r | Map(e.Rights));
        var owner = ownerReads && acl.Owner is { } o && token.ContainsKey(o) ? token[o] : null;
        if ((denied & rights) != 0 || ((allowed & rights) != rights && owner is null))
            return [];
        IEnumerable<string> names = mine.Where(e => e.Allow && (Map(e.Rights) & rights) != 0).Select(e => token[e.Sid]);
        if (owner is not null)
            names = names.Append(owner);
        return [.. names.Distinct()];
    }

    static int Map(int rights) =>
        rights
        | ((rights & (GenericRead | GenericAll)) != 0 ? ReadData : 0)
        | ((rights & (GenericWrite | GenericAll)) != 0 ? WriteData : 0);
}

public static partial class Doctor
{
    public const string DockerEngineCheck = "docker engine", HyperVCheck = "hyper-v", WslDisksCheck = "wsl disks";

    /// <summary>
    /// What a program running as the user can open of their containers, WSL distributions and VMs,
    /// from account facts alone. A Docker engine pipe or Hyper-V membership is a finding with steps;
    /// a WSL disk the user owns is a passing line that informs, since Windows gives the owner that file.
    /// </summary>
    public static IEnumerable<DoctorCheck> Reach(ReachFacts facts)
    {
        var open = facts.Engines.Where(e => e.GrantedTo.Count > 0).ToArray();
        if (open.Length > 0)
        {
            var to = open.SelectMany(e => e.GrantedTo).Distinct().ToArray();
            var windows = open.Any(e => e.Kind == EngineKind.Windows);
            yield return new(DockerEngineCheck, DoctorStatus.Warn,
                $"{string.Join(", ", open.Select(e => e.Name))} {(open.Length == 1 ? "is" : "are")} open to {string.Join(" and ", to)}, so every program you run can, while Docker runs, "
                + "read every container's environment, start a shell in any container and mount your files into one"
                + (windows ? ". One serves Windows containers, whose engine runs as SYSTEM when it is on: through it, a program is administrator on this PC" : ""),
                new ReachGuide(ReachTopic.DockerEngine, DirectGrant: to.Contains(YourAccount)));
        }

        switch (facts.HyperV)
        {
            case HyperVAccess.Member:
                yield return new(HyperVCheck, DoctorStatus.Warn,
                    "you are in Hyper-V Administrators, which Windows doesn't hold back behind a UAC prompt: every program you run can export, checkpoint or attach any VM's disk, and checkpoints hold the guest's memory",
                    new ReachGuide(ReachTopic.HyperV));
                break;
            case HyperVAccess.AdminPromptAway:
                yield return new(HyperVCheck, DoctorStatus.Ok, "VMs need an administrator: a program you run has to ask through a UAC prompt first");
                break;
            case HyperVAccess.None:
                yield return new(HyperVCheck, DoctorStatus.Ok, "not in Hyper-V Administrators: no program you run can open a VM");
                break;
        }

        var readable = facts.Distributions
            .Where(d => d.ReadableFor.Count > 0 && !d.Name.StartsWith("docker-desktop", StringComparison.OrdinalIgnoreCase))
            .Select(d => d.Name).ToArray();
        if (readable.Length > 0)
            yield return new(WslDisksCheck, DoctorStatus.Ok,
                $"{(readable.Length == 1 ? "1 distribution's disk is a file" : $"{readable.Length} distributions' disks are files")} you own: {string.Join(", ", readable)}. "
                + "Any program you run can copy one and read it, even while it is stopped, so keep secrets out of it: pass them in with tir run --only NAME -- wsl, with NAME in WSLENV");
    }

    /// <summary>How <see cref="ReachFacts"/> names the user's own SID, beside group names.</summary>
    public const string YourAccount = "your account";
}

public enum ReachTopic { DockerEngine, HyperV, DevcontainerForwarding }

/// <summary>
/// Steps outside Tiresias to close a path into the user's containers or VMs. Tiresias runs none:
/// each needs Docker quit, an administrator, or a change inside a guest.
/// </summary>
/// <param name="DirectGrant">The engine pipe names the user's account itself, so leaving <c>docker-users</c> doesn't close it.</param>
public sealed record ReachGuide(ReachTopic Topic, bool DirectGrant = false) : DoctorFix
{
    /// <summary>The page whose <i>Findings</i> explain each topic, relative to the repository.</summary>
    public const string Page = "docs/containers-and-vms.md";

    public override string Instruction => Topic switch
    {
        ReachTopic.DockerEngine => DirectGrant
            ? "quit Docker Desktop when you don't use it: its pipe closes with it. The pipe names your account itself, so leaving docker-users doesn't close it"
            : "quit Docker Desktop when you don't use it: its pipe closes with it. If you don't use Docker, leave the group as an administrator: Remove-LocalGroupMember -Group docker-users -Member \"$env:USERDOMAIN\\$env:USERNAME\"",
        ReachTopic.DevcontainerForwarding => "if your containers don't need them, add to VS Code's user settings: "
            + "\"dev.containers.gitCredentialHelperConfigLocation\": \"none\", \"dev.containers.dockerCredentialHelper\": false",
        _ => "if you don't manage VMs, leave the group as an administrator: Remove-LocalGroupMember -SID S-1-5-32-578 -Member \"$env:USERDOMAIN\\$env:USERNAME\". "
            + "Inside each guest, turn on BitLocker with a virtual TPM so its disk and checkpoints are ciphertext to the host",
    };
}
