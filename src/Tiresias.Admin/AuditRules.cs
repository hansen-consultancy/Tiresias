using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Tiresias.AdminTier;

namespace Tiresias.Admin;

/// <summary>
/// The audit rule on a decoy file (Everyone, <c>FILE_READ_DATA</c>, success) and the system audit
/// policy for the File System subcategory. Each file is opened without following a link and judged
/// on its handle (<see cref="AdminAudit.RuleRefusal"/>), and only Tiresias's rule is added or taken
/// away: any other entry in the file's SACL stays. Needs <c>SeSecurityPrivilege</c>, which the
/// service keeps and an elevated administrator has. Linked into the agent too, so the tier's removal
/// can undo it with the service stopped.
/// </summary>
static unsafe partial class AuditRules
{
    static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    /// <summary>Enables <c>SeSecurityPrivilege</c> on this process's token; without it nothing here works.</summary>
    public static void EnablePrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            throw new Win32Exception();
        using (token)
        {
            if (!LookupPrivilegeValueW(null, "SeSecurityPrivilege", out var luid))
                throw new Win32Exception();
            var privileges = new TokenPrivileges { Count = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastPInvokeError() != 0)
                throw new Win32Exception();
        }
    }

    /// <summary>Adds the rule to a held file of <paramref name="userSid"/>'s.</summary>
    /// <returns>Why it wasn't, or <c>null</c>.</returns>
    public static string? Add(string path, string userSid) => Change(path, userSid, add: true);

    /// <summary>Takes Tiresias's rule off a file, if it is still a regular file; whoever owns it now.</summary>
    public static string? Remove(string path) => Change(path, null, add: false);

    static string? Change(string path, string? userSid, bool add)
    {
        using var file = CreateFileW(path, ReadControl | AccessSystemSecurity, FileShareAll, IntPtr.Zero, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics, IntPtr.Zero);
        if (file.IsInvalid)
            return new Win32Exception().Message;
        if (!GetFileInformationByHandle(file, out var info))
            return new Win32Exception().Message;
        var descriptor = Descriptor(file);
        var owner = descriptor.Owner?.Value;
        var refusal = AdminAudit.RuleRefusal((FileAttributes)info.Attributes, info.Links, owner, userSid ?? owner ?? "");
        if (refusal is not null)
            return refusal;
        var sacl = descriptor.SystemAcl ?? new RawAcl(GenericAcl.AclRevision, 1);
        for (var i = sacl.Count - 1; i >= 0; i--)
            if (IsOurs(sacl[i]))
                sacl.RemoveAce(i);
        if (add)
            sacl.InsertAce(sacl.Count, new CommonAce(AceFlags.SuccessfulAccess, AceQualifier.SystemAudit, (int)AdminAudit.ReadData, Everyone, false, null));
        var bytes = new byte[sacl.BinaryLength];
        sacl.GetBinaryForm(bytes, 0);
        fixed (byte* acl = bytes)
        {
            var error = SetSecurityInfo(file, SeFileObject, SaclSecurityInformation, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, (IntPtr)acl);
            return error == 0 ? null : new Win32Exception((int)error).Message;
        }
    }

    static bool IsOurs(GenericAce ace) =>
        ace is CommonAce { AceQualifier: AceQualifier.SystemAudit } audit && audit.SecurityIdentifier == Everyone
        && audit.AccessMask == (int)AdminAudit.ReadData && audit.AuditFlags == AuditFlags.Success;

    static RawSecurityDescriptor Descriptor(SafeFileHandle file)
    {
        var error = GetSecurityInfo(file, SeFileObject, OwnerSecurityInformation | SaclSecurityInformation,
            out _, out _, out _, out _, out var descriptor);
        if (error != 0)
            throw new Win32Exception((int)error);
        try
        {
            var bytes = new byte[GetSecurityDescriptorLength(descriptor)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            return new RawSecurityDescriptor(bytes, 0);
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    /// <summary>Whether the File System subcategory audits success now.</summary>
    public static bool SuccessOn()
    {
        var guid = AdminAudit.FileSystemSubcategory;
        if (!AuditQuerySystemPolicy(&guid, 1, out var policy))
            throw new Win32Exception();
        try
        {
            return (((AuditPolicyInformation*)policy)->AuditingInformation & PolicyAuditSuccess) != 0;
        }
        finally
        {
            AuditFree(policy);
        }
    }

    /// <summary>Turns success auditing of the File System subcategory on or off, leaving its failure setting as it is.</summary>
    public static void SetSuccess(bool on)
    {
        var guid = AdminAudit.FileSystemSubcategory;
        if (!AuditQuerySystemPolicy(&guid, 1, out var current))
            throw new Win32Exception();
        AuditPolicyInformation policy;
        try
        {
            policy = *(AuditPolicyInformation*)current;
        }
        finally
        {
            AuditFree(current);
        }
        // Query answers POLICY_AUDIT_EVENT_NONE (4) for "no auditing"; set takes success/failure bits only.
        var failure = policy.AuditingInformation & PolicyAuditFailure;
        policy.AuditingInformation = failure | (on ? PolicyAuditSuccess : 0);
        if (policy.AuditingInformation == 0)
            policy.AuditingInformation = PolicyAuditNone;
        if (!AuditSetSystemPolicy(&policy, 1))
            throw new Win32Exception();
    }

    const uint ReadControl = 0x00020000;
    const uint AccessSystemSecurity = 0x01000000;
    const uint FileShareAll = 0x7;
    const uint OpenExisting = 3;
    const uint FileFlagOpenReparsePoint = 0x00200000;
    const uint FileFlagBackupSemantics = 0x02000000;
    const int SeFileObject = 1;
    const uint OwnerSecurityInformation = 0x1;
    const uint SaclSecurityInformation = 0x8;
    const uint TokenAdjustPrivileges = 0x20;
    const uint TokenQuery = 0x8;
    const uint SePrivilegeEnabled = 0x2;
    const uint PolicyAuditSuccess = 0x1;
    const uint PolicyAuditFailure = 0x2;
    const uint PolicyAuditNone = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleFileInformation
    {
        public uint Attributes;
        public uint CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct TokenPrivileges
    {
        public uint Count;
        public long Luid;
        public uint Attributes;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint info, out IntPtr owner, out IntPtr group,
        out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [LibraryImport("advapi32.dll")]
    private static partial uint SetSecurityInfo(SafeFileHandle handle, int objectType, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityDescriptorLength(IntPtr descriptor);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr LocalFree(IntPtr memory);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValueW(string? system, string name, out long luid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        ref TokenPrivileges state, uint length, IntPtr previous, IntPtr returned);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AuditQuerySystemPolicy(Guid* subcategories, uint count, out IntPtr policy);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AuditSetSystemPolicy(AuditPolicyInformation* policy, uint count);

    [LibraryImport("advapi32.dll")]
    private static partial void AuditFree(IntPtr buffer);
}
