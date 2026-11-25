namespace Tiresias.Client;

/// <summary>
/// Who else manages this PC, as Windows records it without admin rights: the Active Directory domain
/// it is joined to, whether it is joined to Microsoft Entra ID (a device only registered with a work
/// account is not), and whether it is enrolled in device management.
/// </summary>
public sealed record Management(string? Domain, bool EntraJoined, bool DeviceManagement)
{
    public static readonly Management None = new(null, false, false);

    public bool IsManaged => Domain is not null || EntraJoined || DeviceManagement;

    /// <summary>
    /// Whether any device management enrollment (<c>HKLM\SOFTWARE\Microsoft\Enrollments</c>, one key
    /// each) is live: a provider named and its state enrolled (1). Windows leaves keys behind for
    /// enrollments that were never finished or were removed; those don't count.
    /// </summary>
    public static bool Enrolled(IEnumerable<(string? Provider, int? State)> enrollments) =>
        enrollments.Any(e => !string.IsNullOrWhiteSpace(e.Provider) && e.State == 1);
}

public static partial class Doctor
{
    public const string ManagedCheck = "managed PC";

    /// <summary>
    /// On a managed PC, machine-wide software is the administrator's (docs/attack-surface.md,
    /// "Findings"): it stays listed under Installed, but the surface checks judge only what the user
    /// installed. Blocked programs are judged wherever they are: one already behaved like malware.
    /// </summary>
    public static (StartupEntry[] Startup, UninstallEntry[] Installed) Judged(Management management, StartupEntry[] startup, UninstallEntry[] installed) =>
        management.IsManaged
            ? ([.. startup.Where(e => e.Where != StartupEntry.MachineRunKey)], [.. installed.Where(e => !e.Machine)])
            : (startup, installed);

    /// <summary>The line saying why machine-wide software raises nothing on a managed PC; none on one that isn't.</summary>
    public static IEnumerable<DoctorCheck> Managed(Management management)
    {
        if (!management.IsManaged)
            yield break;
        string[] by =
        [
            .. management.Domain is { } domain ? [$"joined to the {domain} domain"] : Array.Empty<string>(),
            .. management.EntraJoined ? ["joined to Microsoft Entra ID"] : Array.Empty<string>(),
            .. management.DeviceManagement ? ["enrolled in device management"] : Array.Empty<string>(),
        ];
        yield return new(ManagedCheck, DoctorStatus.Ok,
            $"This PC is {string.Join(" and ", by)}, so software installed for everyone is your administrator's: "
            + "it is listed under Installed, but only what you installed yourself is checked");
    }
}
