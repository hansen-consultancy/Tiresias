namespace Tiresias.AdminTier;

public enum AdminInstallStep
{
    StopService,
    /// <summary>Replace the files in <c>%ProgramFiles%\Tiresias\Admin</c> with the app's copy.</summary>
    CopyFiles,
    /// <summary>Create <c>%ProgramData%\Tiresias\Admin</c>, or set its owner and ACL right again.</summary>
    SecureStateFolder,
    CreateService,
    /// <summary>Set an existing service's binary, account, start type, privileges and failure actions again.</summary>
    ConfigureService,
    StartService,
    /// <summary>Give each user's held decoy set back to that user's agent, read from the state folder once the service has stopped.</summary>
    HandBackDecoys,
    DeleteService,
    DeleteFiles,
    /// <summary>Only when every held set went back: one that didn't stays there, and an install picks it up again.</summary>
    DeleteStateFolder,
}

/// <summary>The exit code of <c>Tiresias.exe --admin-tier install|remove</c>, which the app reads back after the UAC prompt.</summary>
public enum AdminSetupResult
{
    Done = 0,
    Failed = 1,
    /// <summary>This copy of the app has no <c>admin\</c> folder to install from: a development build.</summary>
    FilesMissing = 2,
    /// <summary>Not <c>install</c>, <c>remove</c> or <c>release-decoys</c>.</summary>
    Usage = 3,
    /// <summary>The service was set up but stopped again at once: its state folder or pipe name isn't its own.</summary>
    DidNotStart = 4,
}

/// <summary>The service as the Service Control Manager has it now.</summary>
public sealed record AdminServiceFacts(bool Exists, bool Running);

/// <summary>
/// What <c>Tiresias.exe --admin-tier install|remove</c> does, given the service as it is. Install is
/// idempotent: run again it repairs (or updates) everything it set, so one step serves first setup,
/// a repair and an update. Remove leaves nothing behind, whatever state it finds.
/// </summary>
public static class AdminInstallPlan
{
    public static IReadOnlyList<AdminInstallStep> Install(AdminServiceFacts service) =>
    [
        // The running binary is locked; it is replaced only stopped.
        .. service.Running ? [AdminInstallStep.StopService] : Array.Empty<AdminInstallStep>(),
        AdminInstallStep.CopyFiles,
        AdminInstallStep.SecureStateFolder,
        service.Exists ? AdminInstallStep.ConfigureService : AdminInstallStep.CreateService,
        AdminInstallStep.StartService,
    ];

    public static IReadOnlyList<AdminInstallStep> Remove(AdminServiceFacts service) =>
    [
        .. service.Running ? [AdminInstallStep.StopService] : Array.Empty<AdminInstallStep>(),
        // Stopped first, so nothing listens on a set or changes it while it goes back.
        AdminInstallStep.HandBackDecoys,
        .. service.Exists ? [AdminInstallStep.DeleteService] : Array.Empty<AdminInstallStep>(),
        AdminInstallStep.DeleteFiles,
        AdminInstallStep.DeleteStateFolder,
    ];
}

/// <summary>
/// Who may own a folder the service keeps state in or runs from. A folder made by anyone else (a
/// user can create folders in <c>%ProgramData%</c> before the service ever runs) can be changed back
/// by its owner, so it is replaced, never trusted.
/// </summary>
public static class AdminFolders
{
    public const string SystemSid = "S-1-5-18";
    public const string AdministratorsSid = "S-1-5-32-544";

    public static bool Trusted(bool isReparsePoint, string? ownerSid) =>
        !isReparsePoint && ownerSid is SystemSid or AdministratorsSid;
}
