using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// The programs that would stop Velopack moving the install folder: those run from it, and those
/// whose working folder is in it. Velopack checks only the first kind, and Restart Manager sees
/// neither (a working folder is a handle on the folder, not on a file), so an update failed with
/// nothing named (#149). Programs of another account or elevated can't be read and are left out.
/// </summary>
static class InstallFolderUsers
{
    /// <returns>"name (PID n)" for each, this process left out.</returns>
    public static IReadOnlyList<string> Find(string installRoot)
    {
        var found = new List<string>();
        var self = Environment.ProcessId;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id == self)
                    continue;
                if (UpdatePlan.InInstallFolder(ProgramOf(process), installRoot) || UpdatePlan.InInstallFolder(WorkingFolder(process.Id), installRoot))
                    found.Add($"{process.ProcessName} (PID {process.Id})");
            }
        }
        return found;
    }

    static string? ProgramOf(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return null; // Exited, elevated or another account's.
        }
    }

    const int QueryInformation = 0x0400, VmRead = 0x0010;

    // 64-bit layouts (x64 and Arm64): PEB.ProcessParameters at 0x20, then
    // RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath (a UNICODE_STRING) at 0x38.
    const int ParametersOffset = 0x20, CurrentDirectoryOffset = 0x38;

    /// <summary>The process's working folder, read from its PEB; <c>null</c> when it can't be read.</summary>
    static string? WorkingFolder(int pid)
    {
        if (!Environment.Is64BitProcess)
            return null;
        var handle = OpenProcess(QueryInformation | VmRead, false, pid);
        if (handle == IntPtr.Zero)
            return null;
        try
        {
            var info = new ProcessBasicInformation();
            if (NtQueryInformationProcess(handle, 0, ref info, Marshal.SizeOf<ProcessBasicInformation>(), out _) != 0
                || Read(handle, info.PebBaseAddress + ParametersOffset, 8) is not { } parameters
                || Read(handle, (IntPtr)BitConverter.ToInt64(parameters) + CurrentDirectoryOffset, 16) is not { } directory)
                return null;
            int length = BitConverter.ToUInt16(directory, 0);
            return length == 0 || Read(handle, (IntPtr)BitConverter.ToInt64(directory, 8), length) is not { } text
                ? null
                : Encoding.Unicode.GetString(text);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    static byte[]? Read(IntPtr process, IntPtr address, int size)
    {
        var buffer = new byte[size];
        return ReadProcessMemory(process, address, buffer, size, out var read) && read == size ? buffer : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessBasicInformation
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr process, int informationClass, ref ProcessBasicInformation information, int length, out int returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [Out] byte[] buffer, int size, out nint read);
}
