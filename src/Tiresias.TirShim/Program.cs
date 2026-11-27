using System.Runtime.InteropServices;
using Tiresias.App.Logic;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

/// <summary>
/// Runs the real <c>tir.exe</c> named in <c>tir.path</c> beside this file with this process's own
/// command line, console, standard handles and working folder, waits for it and exits with its
/// code. Ctrl+C reaches both through the console; this process ignores it and waits for tir to
/// finish. A kill-on-close job ends tir when this process is killed, while what tir starts breaks
/// away from the job, as when tir itself is killed.
/// </summary>
internal static unsafe partial class Program
{
    static int Main()
    {
        var pointer = Path.Combine(AppContext.BaseDirectory, TirShim.PointerFile);
        var target = ReadPointer(pointer);
        if (target is null || !File.Exists(target))
        {
            Console.Error.WriteLine($"tir: {target ?? pointer} is missing. Start the Tiresias app once to set tir up again.");
            return 1;
        }

        SetConsoleCtrlHandler(&IgnoreControl, true);
        var commandLine = TirShim.CommandLine(target, Marshal.PtrToStringUni(GetCommandLineW())!) + '\0';
        GetStartupInfoW(out var startup);
        ProcessInformation process;
        fixed (char* line = commandLine)
        {
            if (!CreateProcessW(target, line, 0, 0, true, CreateSuspended, 0, null, ref startup, out process))
            {
                Console.Error.WriteLine($"tir: can't start {target} (error {Marshal.GetLastPInvokeError()}).");
                return 1;
            }
        }
        var job = KillOnClose();
        if (job != 0)
            _ = AssignProcessToJobObject(job, process.Process);
        _ = ResumeThread(process.Thread);
        CloseHandle(process.Thread);
        _ = WaitForSingleObject(process.Process, uint.MaxValue);
        return GetExitCodeProcess(process.Process, out var code) ? (int)code : 1;
    }

    /// <summary>The app replaces the pointer by a rename, so a read can meet it mid-swap: try again briefly.</summary>
    static string? ReadPointer(string path)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return File.ReadAllText(path).Trim() is { Length: > 0 } text ? text : null;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (Exception e) when ((e is IOException or UnauthorizedAccessException) && attempt < 5)
            {
                Thread.Sleep(50);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }
    }

    [UnmanagedCallersOnly]
    static int IgnoreControl(uint type) => 1;

    static nint KillOnClose()
    {
        var job = CreateJobObjectW(0, null);
        if (job == 0)
            return 0;
        var limits = new ExtendedLimitInformation { Basic = new BasicLimitInformation { LimitFlags = KillOnJobClose | SilentBreakawayOk } };
        return SetInformationJobObject(job, ExtendedLimitInformationClass, &limits, (uint)sizeof(ExtendedLimitInformation)) ? job : 0;
    }

    const uint CreateSuspended = 0x4;
    const uint KillOnJobClose = 0x2000, SilentBreakawayOk = 0x1000;
    const int ExtendedLimitInformationClass = 9;

    [StructLayout(LayoutKind.Sequential)]
    struct StartupInfo
    {
        public int Size;
        public nint Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, Reserved2Size;
        public nint Reserved2, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public nint Process, Thread;
        public int ProcessId, ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimitInformation
    {
        public BasicLimitInformation Basic;
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadTransfers, WriteTransfers, OtherTransfers;
        public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCommandLineW();

    [LibraryImport("kernel32.dll")]
    private static partial void GetStartupInfoW(out StartupInfo info);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleCtrlHandler(delegate* unmanaged<uint, int> handler, [MarshalAs(UnmanagedType.Bool)] bool add);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcessW(string application, char* commandLine, nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, nint environment, string? currentDirectory,
        ref StartupInfo startup, out ProcessInformation information);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateJobObjectW(nint attributes, string? name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(nint job, int infoClass, void* info, uint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(nint job, nint process);

    [LibraryImport("kernel32.dll")]
    private static partial uint ResumeThread(nint thread);

    [LibraryImport("kernel32.dll")]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(nint process, out uint code);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
