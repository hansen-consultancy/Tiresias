using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Tiresias.Agent;

[SupportedOSPlatform("windows")]
internal static class BrokerVaultAccess
{
    /// <summary>Grants the service read access to the vault and removes the folder-wide grant from older installs.</summary>
    internal static void Set(string path, IdentityReference service, bool grant)
    {
        var root = Path.GetPathRoot(path);
        if (root is not { Length: 3 } || root[1] != ':' || new DriveInfo(root).DriveType != DriveType.Fixed)
        {
            if (grant)
                throw new InvalidOperationException("The service vault must be a file on a local fixed drive.");
            return;
        }
        var file = new FileInfo(path);
        if (file.Directory is { Exists: true } folder)
        {
            var sid = service.Translate(typeof(SecurityIdentifier));
            var inheritedRead = new FileSystemAccessRule(sid, FileSystemRights.Read,
                InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow);
            var folderAcl = folder.GetAccessControl(AccessControlSections.Access);
            if (folderAcl.GetAccessRules(true, false, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().Any(rule =>
                rule.IdentityReference == sid && rule.FileSystemRights == inheritedRead.FileSystemRights &&
                rule.InheritanceFlags == inheritedRead.InheritanceFlags && rule.PropagationFlags == PropagationFlags.None &&
                rule.AccessControlType == AccessControlType.Allow))
            {
                folderAcl.RemoveAccessRuleSpecific(inheritedRead);
                folder.SetAccessControl(folderAcl);
            }
        }
        if (!grant && !file.Exists)
            return;
        // Keep the same file open from reading its ACL until applying the change.
        using var stream = file.Create(FileMode.Open, FileSystemRights.Read | FileSystemRights.ChangePermissions,
            FileShare.Read, 4096, FileOptions.None, null);
        var acl = stream.GetAccessControl();
        var read = new FileSystemAccessRule(service, FileSystemRights.Read, AccessControlType.Allow);
        if (grant)
            acl.AddAccessRule(read);
        else
            acl.RemoveAccessRuleSpecific(read);
        stream.SetAccessControl(acl);
    }
}
