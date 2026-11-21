using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Tiresias.Decoys;

namespace Tiresias.Agent;

/// <summary>A decoy file was opened: which, by whom (or that it couldn't be told), and the opener's full path when it could be read.</summary>
/// <param name="ImagePath">The opener's full image path, read while it waited; <c>null</c> when only the snapshot's file name is known.</param>
sealed record DecoyFileOpened(string File, DecoyOpener Opener, string? ImagePath, DateTimeOffset At);

/// <summary>
/// The read tripwire (docs/decoys.md, layer 2): an oplock on every decoy file, so a process
/// opening one waits until Tiresias releases it; meanwhile it is named by the thread that wakes
/// (<see cref="OpenerNaming"/>). The opener still gets the file, about 55 ms late: this names, it
/// doesn't stop. A break uses the oplock up, so each file has a thread that takes it again as soon
/// as the opener's handle allows. A file that is gone or can't be opened is logged and left
/// unwatched; nothing here throws into the agent.
/// </summary>
sealed partial class DecoyTripwire : IDisposable
{
    /// <summary>How long a break is held before the release: the false-positive filter, and the reader's delay.</summary>
    static readonly TimeSpan Settle = TimeSpan.FromMilliseconds(20);

    /// <summary>How long after the release the woken opener is looked for; short, since every millisecond lets an innocent thread wake too.</summary>
    static readonly TimeSpan Woke = TimeSpan.FromMilliseconds(3);

    static readonly TimeSpan MaxRetry = TimeSpan.FromSeconds(1);

    readonly IReadOnlyList<string> files;
    readonly ManualResetEvent stopping = new(false);
    readonly List<Thread> watching = [];
    readonly ThreadSnapshots snapshots = new();
    bool finerTimer;

    public DecoyTripwire(IReadOnlyList<string> files) => this.files = files;

    /// <summary>Raised on a pool thread after the opener was released, so watching resumes meanwhile. Never carries a file's content.</summary>
    public event Action<DecoyFileOpened>? Opened;

    public event Action<string>? Log;

    public void Start()
    {
        if (!Environment.Is64BitProcess)
        {
            Log?.Invoke("The decoy read tripwire needs a 64-bit Tiresias; decoy files are watched only for their credentials being used.");
            return;
        }
        // Sleep(3) would otherwise last a whole 15.6 ms tick, letting more innocent threads wake.
        finerTimer = timeBeginPeriod(1) == 0;
        foreach (var file in files)
        {
            var thread = new Thread(() => WatchOrLog(file)) { IsBackground = true, Name = "decoy tripwire" };
            watching.Add(thread);
            thread.Start();
        }
    }

    /// <summary>A thread's exception would end the agent: a failure stops watching this file, and says so.</summary>
    void WatchOrLog(string file)
    {
        try
        {
            Watch(file);
        }
        catch (Exception e)
        {
            Log?.Invoke($"The read tripwire stopped watching {file} ({e.Message}); opening it goes unseen until the decoys change.");
        }
    }

    void Watch(string file)
    {
        var retry = TimeSpan.Zero;
        while (!stopping.WaitOne(retry))
        {
            var oplock = Oplock.Request(file, out var error);
            if (oplock is null)
            {
                if (error is not (ErrorFileNotFound or ErrorPathNotFound or ErrorAccessDenied or ErrorInvalidFunction or ErrorNotSupported))
                {
                    // Busy: the last opener still has it open, so no oplock can be granted yet.
                    retry = retry == TimeSpan.Zero ? TimeSpan.FromMilliseconds(20) : TimeSpan.FromTicks(Math.Min(retry.Ticks * 2, MaxRetry.Ticks));
                    continue;
                }
                Log?.Invoke($"The read tripwire can't watch {file} ({new Win32Exception(error).Message}); opening it goes unseen until the decoys change.");
                return;
            }
            retry = TimeSpan.Zero;
            using (oplock)
            {
                if (WaitHandle.WaitAny([oplock.Broken, stopping]) != 0)
                    return;
                var opened = Name(file, oplock);
                Task.Run(() => Opened?.Invoke(opened));
            }
        }
    }

    /// <summary>Holds the break while the opener's thread settles, releases it, and sees whose thread woke.</summary>
    DecoyFileOpened Name(string file, Oplock oplock)
    {
        var at = DateTimeOffset.UtcNow;
        var tick = InterruptTick();
        var third = Settle / 3;
        Thread.Sleep(third);
        var first = snapshots.Take();
        Thread.Sleep(Settle - third);
        var stuck = OpenerNaming.Stuck(tick, [first, snapshots.Take()]);
        // While they wait the candidates are certainly alive, so their pids name them; a short opener is gone soon after.
        var paths = stuck.Select(t => t.ProcessId).Distinct().ToDictionary(pid => pid, ImagePaths.Of);
        oplock.Release();
        Thread.Sleep(Woke);
        var opener = OpenerNaming.Name(stuck, first, snapshots.Take());
        return new(file, opener, opener is DecoyOpener.Named named ? paths.GetValueOrDefault(named.ProcessId) : null, at);
    }

    /// <summary>KUSER_SHARED_DATA.TickCount's low part: the clock a thread's wait start is counted in.</summary>
    static unsafe uint InterruptTick() => *(uint*)0x7FFE0320;

    public void Dispose()
    {
        stopping.Set();
        foreach (var thread in watching)
            thread.Join(TimeSpan.FromSeconds(2));
        if (finerTimer)
            finerTimer = timeEndPeriod(1) != 0;
        // A thread still naming (it can't take longer than the join) would touch a disposed event, so keep it.
        if (watching.All(t => !t.IsAlive))
            stopping.Dispose();
    }

    const int ErrorInvalidFunction = 1, ErrorFileNotFound = 2, ErrorPathNotFound = 3, ErrorAccessDenied = 5, ErrorNotSupported = 50;

    /// <summary>
    /// A read-handle-write oplock on one file, on a handle that shares everything: the user and
    /// every other program can still read, change, rename and delete the file. Disposing releases it.
    /// </summary>
    sealed unsafe class Oplock : IDisposable
    {
        const uint GenericRead = 0x80000000, ShareAll = 7, OpenExisting = 3, Overlapped = 0x40000000;
        const uint RequestOplock = 0x90240;
        const uint CacheRead = 1, CacheHandle = 2, CacheWrite = 4, RequestFlag = 1;
        const int ErrorIoPending = 997;

        readonly SafeFileHandle handle;
        readonly NativeOverlapped* overlapped;
        readonly OutputBuffer* output;
        bool released;

        public ManualResetEvent Broken { get; } = new(false);

        Oplock(SafeFileHandle handle)
        {
            this.handle = handle;
            overlapped = (NativeOverlapped*)NativeMemory.AllocZeroed((nuint)sizeof(NativeOverlapped));
            overlapped->EventHandle = Broken.SafeWaitHandle.DangerousGetHandle();
            output = (OutputBuffer*)NativeMemory.AllocZeroed((nuint)sizeof(OutputBuffer));
        }

        /// <returns>The oplock, pending until a break; <c>null</c> with the Win32 error when the file can't be opened or the oplock isn't granted.</returns>
        public static Oplock? Request(string path, out int error)
        {
            var handle = CreateFileW(path, GenericRead, ShareAll, 0, OpenExisting, Overlapped, 0);
            if (handle.IsInvalid)
            {
                error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                return null;
            }
            var oplock = new Oplock(handle);
            var input = new InputBuffer { Version = 1, Length = (ushort)sizeof(InputBuffer), Level = CacheRead | CacheHandle | CacheWrite, Flags = RequestFlag };
            if (DeviceIoControl(handle, RequestOplock, &input, sizeof(InputBuffer), oplock.output, sizeof(OutputBuffer), out _, oplock.overlapped))
            {
                // Completed at once: broken already, by an open that came first. Try again.
                error = 0;
                oplock.Dispose();
                return null;
            }
            error = Marshal.GetLastPInvokeError();
            if (error == ErrorIoPending)
                return oplock;
            oplock.Dispose();
            return null;
        }

        /// <summary>Closes the handle, which releases a broken oplock: the waiting opener proceeds.</summary>
        public void Release()
        {
            if (released)
                return;
            released = true;
            // Not broken (stopping): cancel the request and wait for it, so the buffers it writes outlive it.
            if (!Broken.WaitOne(0) && CancelIoEx(handle, overlapped))
                GetOverlappedResult(handle, overlapped, out _, true);
            handle.Dispose();
        }

        public void Dispose()
        {
            Release();
            NativeMemory.Free(overlapped);
            NativeMemory.Free(output);
            Broken.Dispose();
        }

        [StructLayout(LayoutKind.Sequential)]
        struct InputBuffer
        {
            public ushort Version, Length;
            public uint Level, Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct OutputBuffer
        {
            public ushort Version, Length;
            public uint Original, New, Flags, AccessMode;
            public ushort ShareMode, Reserved;
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool DeviceIoControl(SafeFileHandle handle, uint code, void* input, int inputLength, void* output, int outputLength, out int returned, NativeOverlapped* overlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CancelIoEx(SafeFileHandle handle, NativeOverlapped* overlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool GetOverlappedResult(SafeFileHandle handle, NativeOverlapped* overlapped, out int transferred, [MarshalAs(UnmanagedType.Bool)] bool wait);

    [LibraryImport("winmm.dll")]
    private static partial uint timeBeginPeriod(uint period);

    [LibraryImport("winmm.dll")]
    private static partial uint timeEndPeriod(uint period);
}
