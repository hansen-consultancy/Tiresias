using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Tiresias.AdminTier;

namespace Tiresias.Admin;

/// <summary>
/// Freezes processes in a job object (docs/admin-tier.md, <i>Stopping the program</i>) and thaws
/// them. The job is named, with an ACL of SYSTEM and Administrators only, so the user's programs
/// can't open it; each frozen process is given a handle to it that allows nothing but waiting, which
/// keeps the name alive while any of them runs, so the job is found again after the service
/// restarts (a job outlives its last handle but its name doesn't, and a freeze can't be undone
/// without one). Checked by hand, unelevated on the author's own processes: a job freeze is not
/// undone by <c>NtResumeProcess</c> or <c>ResumeThread</c> from the user's own token, and Task
/// Manager still ends a frozen process. Linked into the agent, whose elevated removal thaws with the
/// service stopped.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static partial class ProcessFreezer
{
    /// <summary>Every running process, with what <see cref="AdminFreeze"/> judges it by.</summary>
    public static IReadOnlyList<FreezeCandidate> Running()
    {
        using var snapshot = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snapshot.IsInvalid)
            throw new Win32Exception();
        var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>() };
        var found = new List<FreezeCandidate>();
        for (var more = Process32FirstW(snapshot, ref entry); more; more = Process32NextW(snapshot, ref entry))
            if (Describe((int)entry.ProcessId, (int)entry.ParentId) is { } process)
                found.Add(process);
        return found;
    }

    static FreezeCandidate? Describe(int id, int parent)
    {
        using var handle = OpenProcess(QueryLimitedInformation, false, (uint)id);
        if (handle.IsInvalid || Started(handle) is not { } started)
            return null;
        return new(id, parent, started, Image(handle), Owner(handle), IsProcessCritical(handle, out var critical) && critical);
    }

    static DateTime? Started(SafeProcessHandle process) =>
        GetProcessTimes(process, out var created, out _, out _, out _) ? DateTime.FromFileTimeUtc(created) : null;

    static unsafe string? Image(SafeProcessHandle process)
    {
        var buffer = new char[1024];
        var length = (uint)buffer.Length;
        fixed (char* p = buffer)
            return QueryFullProcessImageNameW(process, 0, p, ref length) ? new string(buffer, 0, (int)length) : null;
    }

    static string? Owner(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token))
            return null;
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            return identity.User?.Value;
    }

    /// <summary>
    /// Puts the processes into a new job named <paramref name="job"/> and freezes it. A process
    /// that ended, or whose id now belongs to a later process, is skipped.
    /// </summary>
    /// <returns>How many were frozen; none when the name was taken already (by someone else: the name is new).</returns>
    public static int Freeze(string job, IReadOnlyList<FrozenProcess> processes)
    {
        var descriptor = new RawSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes { Length = (uint)Marshal.SizeOf<SecurityAttributes>(), Descriptor = pinned.AddrOfPinnedObject() };
            using var handle = CreateJobObjectW(ref attributes, job);
            if (handle.IsInvalid)
                throw new Win32Exception();
            if (Marshal.GetLastPInvokeError() == ErrorAlreadyExists)
                return 0;
            var members = new List<SafeProcessHandle>();
            try
            {
                foreach (var process in processes)
                {
                    var opened = OpenProcess(SetQuota | Terminate | DupHandle | QueryLimitedInformation, false, (uint)process.ProcessId);
                    if (!opened.IsInvalid && Started(opened) == process.Started && AssignProcessToJobObject(handle, opened))
                        members.Add(opened);
                    else
                        opened.Dispose();
                }
                if (members.Count == 0 || !SetFrozen(handle, true))
                    return 0;
                // A handle that allows only waiting, in each frozen process: it keeps the job's name while they run.
                foreach (var member in members)
                    DuplicateHandle(GetCurrentProcess(), handle, member, out _, Synchronize, false, 0);
                return members.Count;
            }
            finally
            {
                foreach (var member in members)
                    member.Dispose();
            }
        }
        finally
        {
            pinned.Free();
        }
    }

    /// <summary>Thaws the job named <paramref name="job"/>.</summary>
    /// <returns>Whether it was found and thawed; it isn't found once every process in it has ended.</returns>
    public static bool Thaw(string job)
    {
        using var handle = OpenJobObjectW(JobSetAttributes | JobQuery, false, job);
        return !handle.IsInvalid && SetFrozen(handle, false);
    }

    static bool SetFrozen(SafeJobHandle job, bool frozen)
    {
        var info = new FreezeInformation { Flags = FreezeOperation, Freeze = (byte)(frozen ? 1 : 0) };
        // Only NtSetInformationJobObject takes this class; SetInformationJobObject answers ERROR_INVALID_PARAMETER.
        return NtSetInformationJobObject(job, JobObjectFreezeInformation, ref info, (uint)Marshal.SizeOf<FreezeInformation>()) == 0;
    }

    sealed class SafeJobHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
    {
        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    const uint SnapProcess = 0x2;
    const uint QueryLimitedInformation = 0x1000;
    const uint SetQuota = 0x0100;
    const uint Terminate = 0x0001;
    const uint DupHandle = 0x0040;
    const uint TokenQuery = 0x8;
    const uint Synchronize = 0x00100000;
    const uint JobSetAttributes = 0x0002;
    const uint JobQuery = 0x0004;
    const int ErrorAlreadyExists = 183;
    const int JobObjectFreezeInformation = 18;
    const uint FreezeOperation = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes
    {
        public uint Length;
        public IntPtr Descriptor;
        public int Inherit;
    }

    /// <summary><c>JOBOBJECT_FREEZE_INFORMATION</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    struct FreezeInformation
    {
        public uint Flags;
        public byte Freeze;
        public byte Swap;
        public ushort Reserved;
        public uint HighEdgeFilter;
        public uint LowEdgeFilter;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct ProcessEntry
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint process);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Process32FirstW(SafeFileHandle snapshot, ref ProcessEntry entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Process32NextW(SafeFileHandle snapshot, ref ProcessEntry entry);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint id);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, char* name, ref uint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsProcessCritical(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool critical);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeJobHandle CreateJobObjectW(ref SecurityAttributes attributes, string name);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeJobHandle OpenJobObjectW(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeJobHandle job, SafeProcessHandle process);

    [LibraryImport("ntdll.dll")]
    private static partial int NtSetInformationJobObject(SafeJobHandle job, int infoClass, ref FreezeInformation info, uint length);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DuplicateHandle(IntPtr source, SafeJobHandle handle, SafeProcessHandle target, out IntPtr duplicate,
        uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}
