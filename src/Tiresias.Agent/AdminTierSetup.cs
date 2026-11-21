using System.ComponentModel;
using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using Tiresias.AdminTier;

namespace Tiresias.Agent;

/// <summary>
/// <c>Tiresias.exe --admin-tier install|remove</c>, run elevated after a UAC prompt: carries out
/// <see cref="AdminInstallPlan"/>. The service's files go to <c>%ProgramFiles%</c>, never run from
/// the app's per-user folder; its state folder is made, or made again, so that only SYSTEM and
/// Administrators control it.
/// </summary>
public static class AdminTierSetup
{
    public static string InstallFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tiresias", "Admin");

    static string StateRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tiresias");

    static string StateFolder => Path.Combine(StateRoot, "Admin");

    /// <summary>Where the app carries the service's files: its own <c>admin\</c> folder, filled by the publish.</summary>
    public static string SourceFolder(string appFolder) => Path.Combine(appFolder, "admin");

    const string Binary = "tiresias-admin.exe";

    public static AdminSetupResult Run(string verb, string appFolder)
    {
        try
        {
            var service = AdminService.Query();
            switch (verb)
            {
                case "install":
                    if (!File.Exists(Path.Combine(SourceFolder(appFolder), Binary)))
                        return AdminSetupResult.FilesMissing;
                    foreach (var step in AdminInstallPlan.Install(service.Facts))
                        if (!Do(step, service, appFolder))
                            return AdminSetupResult.DidNotStart;
                    return AdminSetupResult.Done;
                case "remove":
                    foreach (var step in AdminInstallPlan.Remove(service.Facts))
                        Do(step, service, appFolder);
                    return AdminSetupResult.Done;
                default:
                    return AdminSetupResult.Usage;
            }
        }
        catch (Exception e) when (e is Win32Exception or IOException or UnauthorizedAccessException or TimeoutException or InvalidOperationException)
        {
            return AdminSetupResult.Failed;
        }
    }

    /// <returns><c>false</c> when the service stopped again instead of running.</returns>
    static bool Do(AdminInstallStep step, AdminService.State service, string appFolder)
    {
        switch (step)
        {
            case AdminInstallStep.StopService:
                AdminService.Stop();
                break;
            case AdminInstallStep.CopyFiles:
                Retry(() => CopyFiles(SourceFolder(appFolder), InstallFolder));
                break;
            case AdminInstallStep.SecureStateFolder:
                Secure(StateRoot);
                Secure(StateFolder);
                break;
            case AdminInstallStep.CreateService or AdminInstallStep.ConfigureService:
                AdminService.CreateOrConfigure(Path.Combine(InstallFolder, Binary), service.Exists);
                break;
            case AdminInstallStep.StartService:
                return AdminService.Start();
            case AdminInstallStep.DeleteService:
                AdminService.Delete();
                break;
            case AdminInstallStep.DeleteFiles:
                Retry(() => DeleteTree(InstallFolder));
                DeleteIfEmpty(Path.GetDirectoryName(InstallFolder)!);
                break;
            case AdminInstallStep.DeleteStateFolder:
                // Only a folder that is ours: anything else under that name was put there by someone else, and is left alone.
                if (Trusted(StateRoot) && Trusted(StateFolder))
                    DeleteTree(StateFolder);
                if (Trusted(StateRoot))
                    DeleteIfEmpty(StateRoot);
                break;
        }
        return true;
    }

    static void CopyFiles(string from, string to)
    {
        DeleteTree(to);
        foreach (var file in Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(to, Path.GetRelativePath(from, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    /// <summary>
    /// Makes the folder one that only SYSTEM and Administrators control. A user can create folders in
    /// <c>%ProgramData%</c>, so one already there that isn't ours is moved aside (Administrators may
    /// rename any child of it) rather than used: its owner could change its ACL back.
    /// </summary>
    static void Secure(string folder)
    {
        var info = new DirectoryInfo(folder);
        if (info.Exists && !Trusted(folder))
            info.MoveTo($"{folder}.untrusted-{DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture)}");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        foreach (var sid in new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), Administrators })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(folder).Create(security);
        // Someone may have made it between the check and the create: it must be ours now, or nothing is written into it.
        if (!Trusted(folder))
            throw new InvalidOperationException($"{folder} was made by someone else while it was being set up.");
        new DirectoryInfo(folder).SetAccessControl(security);
    }

    static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    static bool Trusted(string folder)
    {
        var info = new DirectoryInfo(folder);
        if (!info.Exists)
            return false;
        var owner = info.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))?.Value;
        return AdminFolders.Trusted(info.Attributes.HasFlag(FileAttributes.ReparsePoint), owner);
    }

    static void DeleteTree(string folder)
    {
        if (Directory.Exists(folder))
            Directory.Delete(folder, recursive: true);
    }

    static void DeleteIfEmpty(string folder)
    {
        if (Directory.Exists(folder) && !Directory.EnumerateFileSystemEntries(folder).Any())
            Directory.Delete(folder);
    }

    /// <summary>A service process that has just stopped can hold its files a moment longer.</summary>
    static void Retry(Action act)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                act();
                return;
            }
            catch (Exception e) when (attempt < 10 && e is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(500);
            }
        }
    }
}
