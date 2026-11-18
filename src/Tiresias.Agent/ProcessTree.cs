using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Agent;

/// <summary>
/// Which shell a <c>tir</c> call came from: a process named by the caller is accepted only when it is
/// an ancestor of the process actually on the pipe, started before it. Read with the least access
/// Windows offers, so an elevated terminal is still recognised by a normal app.
/// </summary>
public static partial class ProcessTree
{
    /// <summary>A launcher can sit between the shell and <c>tir</c> (a <c>.cmd</c> shim, <c>dotnet</c>), so a few levels up are searched.</summary>
    const int MaxDepth = 4;

    /// <returns>The shell, or <c>null</c> when <paramref name="shell"/> is not an ancestor of <paramref name="caller"/>.</returns>
    public static ShellIdentity? ShellOf(int caller, int shell)
    {
        var child = Describe(caller);
        for (var depth = 0; child is not null && depth < MaxDepth; depth++)
        {
            // A parent id is only a number: the real parent may have exited and the id been reused by a later process.
            if (Describe(child.Value.Parent) is not { } parent || parent.Started > child.Value.Started)
                return null;
            if (parent.Id == shell)
                return new(parent.Id, parent.Started, parent.Image);
            child = parent;
        }
        return null;
    }

    /// <summary>The process that started <paramref name="caller"/>, when it is still running and started before it.</summary>
    public static ShellIdentity? ParentOf(int caller) =>
        Describe(caller) is { } child && Describe(child.Parent) is { } parent && parent.Started <= child.Started
            ? new(parent.Id, parent.Started, parent.Image)
            : null;

    /// <summary>Whether the process that had this id and start time is still running.</summary>
    public static bool IsRunning(int id, DateTime started) => Describe(id) is { } process && process.Started == started;

    readonly record struct Info(int Id, int Parent, DateTime Started, string Image);

    static Info? Describe(int id)
    {
        using var handle = OpenProcess(QueryLimitedInformation, false, (uint)id);
        if (handle.IsInvalid)
            return null;
        if (NtQueryInformationProcess(handle, 0, out var basic, Marshal.SizeOf<BasicInformation>(), out _) != 0)
            return null;
        if (!GetProcessTimes(handle, out var created, out _, out _, out _))
            return null;
        var image = new char[1024];
        var length = image.Length;
        var path = QueryFullProcessImageNameW(handle, 0, image, ref length) ? new string(image, 0, length) : $"pid {id}";
        return new(id, (int)basic.InheritedFromUniqueProcessId, DateTime.FromFileTimeUtc(created), path);
    }

    const uint QueryLimitedInformation = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    struct BasicInformation
    {
        public nint ExitStatus;
        public nint PebBaseAddress;
        public nint AffinityMask;
        public nint BasePriority;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(SafeProcessHandle process, int informationClass, out BasicInformation information, int length, out int returned);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref int size);
}
