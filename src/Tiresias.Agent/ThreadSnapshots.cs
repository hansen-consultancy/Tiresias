using System.Runtime.InteropServices;
using Tiresias.Decoys;

namespace Tiresias.Agent;

/// <summary>
/// Every thread on the machine that may be a paused opener (<see cref="OpenerNaming.MayBeOpener"/>),
/// from <c>NtQuerySystemInformation(SystemProcessInformation)</c>: open to any user, for every
/// process, even ones it can't open. About 12 ms with 15,000 threads; one at a time, reusing its buffer.
/// </summary>
sealed partial class ThreadSnapshots
{
    const int SystemProcessInformation = 5, StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    // 64-bit SYSTEM_PROCESS_INFORMATION and SYSTEM_THREAD_INFORMATION (x64 and Arm64 alike).
    const int NextEntry = 0x00, ThreadCount = 0x04, CreateTime = 0x20, ImageNameLength = 0x38, ImageNameBuffer = 0x40, ProcessIdOffset = 0x50, Threads = 0x100;
    const int ThreadSize = 0x50, WaitTime = 0x18, ThreadIdOffset = 0x30, ContextSwitches = 0x40, State = 0x44, WaitReason = 0x48;

    readonly Lock gate = new();
    byte[] buffer = new byte[4 << 20];

    public unsafe ThreadSnapshot Take()
    {
        lock (gate)
        {
            while (true)
            {
                int status, needed;
                fixed (byte* start = buffer)
                    status = NtQuerySystemInformation(SystemProcessInformation, start, buffer.Length, out needed);
                if (status == 0)
                    break;
                if (status != StatusInfoLengthMismatch)
                    throw new InvalidOperationException($"Listing threads failed (NTSTATUS 0x{status:X8}).");
                buffer = new byte[Math.Max(needed + (1 << 16), buffer.Length * 2)];
            }
            var threads = new List<ThreadRow>(1024);
            var processes = new Dictionary<int, ProcessRow>();
            fixed (byte* start = buffer)
            {
                var process = start;
                while (true)
                {
                    var pid = (int)*(long*)(process + ProcessIdOffset);
                    var count = *(int*)(process + ThreadCount);
                    var kept = false;
                    for (var i = 0; i < count; i++)
                    {
                        var thread = process + Threads + i * ThreadSize;
                        var row = new ThreadRow(pid, (int)*(long*)(thread + ThreadIdOffset), *(int*)(thread + State), *(int*)(thread + WaitReason),
                            *(uint*)(thread + WaitTime), *(uint*)(thread + ContextSwitches));
                        if (OpenerNaming.MayBeOpener(row))
                        {
                            threads.Add(row);
                            kept = true;
                        }
                    }
                    if (kept)
                    {
                        var length = *(ushort*)(process + ImageNameLength);
                        var name = *(char**)(process + ImageNameBuffer);
                        var image = name is null || length == 0 ? $"pid {pid}" : new string(name, 0, length / 2);
                        processes[pid] = new(pid, image, DateTimeOffset.FromFileTime(*(long*)(process + CreateTime)));
                    }
                    var next = *(uint*)(process + NextEntry);
                    if (next == 0)
                        break;
                    process += next;
                }
            }
            return new(threads, processes);
        }
    }

    [LibraryImport("ntdll.dll")]
    private static unsafe partial int NtQuerySystemInformation(int informationClass, void* information, int length, out int returned);
}

/// <summary>
/// A process's full image path by its pid, for any process, including services and protected ones
/// the user can't open (<c>SystemProcessIdInformation</c>). <c>null</c> when it has exited.
/// </summary>
static partial class ImagePaths
{
    const int SystemProcessIdInformation = 88;

    public static unsafe string? Of(int pid)
    {
        const int capacity = 1024;
        var name = stackalloc char[capacity];
        var information = new ProcessIdInformation { ProcessId = pid, Length = 0, MaximumLength = capacity * sizeof(char), Buffer = name };
        if (NtQuerySystemInformation(SystemProcessIdInformation, &information, sizeof(ProcessIdInformation), out _) != 0 || information.Length == 0)
            return null;
        return DosPath(new string(name, 0, information.Length / sizeof(char)));
    }

    /// <summary><c>\Device\HarddiskVolume3\x.exe</c> as <c>C:\x.exe</c>; a device no drive letter names stays as it is.</summary>
    static unsafe string DosPath(string device)
    {
        var target = stackalloc char[512];
        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            var drive = $"{letter}:";
            var length = QueryDosDeviceW(drive, target, 512);
            if (length == 0)
                continue;
            var prefix = new string(target);
            if (device.StartsWith(prefix + '\\', StringComparison.OrdinalIgnoreCase))
                return drive + device[prefix.Length..];
        }
        return device;
    }

    [StructLayout(LayoutKind.Sequential)]
    unsafe struct ProcessIdInformation
    {
        public nint ProcessId;
        public ushort Length, MaximumLength;
        public char* Buffer;
    }

    [LibraryImport("ntdll.dll")]
    private static unsafe partial int NtQuerySystemInformation(int informationClass, void* information, int length, out int returned);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial int QueryDosDeviceW(string device, char* target, int length);
}
