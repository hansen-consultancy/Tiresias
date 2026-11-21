using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Agent;

/// <summary>
/// A file or folder opened without following a link (<c>FILE_FLAG_OPEN_REPARSE_POINT</c>), with what
/// its handle says about it: attributes, hard links and final path. Read from the handle, not the
/// path, so what is checked is what is then read.
/// </summary>
sealed unsafe partial class SourceHandle : IDisposable
{
    public SafeFileHandle Handle { get; }
    public FileAttributes Attributes { get; }
    public uint Links { get; }
    public string FinalPath { get; }

    SourceHandle(SafeFileHandle handle)
    {
        Handle = handle;
        if (!GetFileInformationByHandle(handle, out var info))
            throw new Win32Exception();
        Attributes = (FileAttributes)info.Attributes;
        Links = info.Links;
        var buffer = new char[1024];
        uint length;
        fixed (char* p = buffer)
            length = GetFinalPathNameByHandleW(handle, p, (uint)buffer.Length, 0);
        if (length == 0 || length >= buffer.Length)
            throw new Win32Exception();
        FinalPath = new string(buffer, 0, (int)length);
    }

    public static SourceHandle Open(string path, bool directory)
    {
        var flags = FileFlagOpenReparsePoint | (directory ? FileFlagBackupSemantics : 0);
        var handle = CreateFileW(path, directory ? FileReadAttributes : GenericRead, FileShareRead, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception();
        try
        {
            return new(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public void Dispose() => Handle.Dispose();

    const uint GenericRead = 0x80000000;
    const uint FileReadAttributes = 0x0080;
    const uint FileShareRead = 0x1;
    const uint OpenExisting = 3;
    const uint FileFlagOpenReparsePoint = 0x00200000;
    const uint FileFlagBackupSemantics = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleFileInformation
    {
        public uint Attributes;
        // Three FILETIMEs: two DWORDs each, 4-byte aligned, so not ulong (which would pad after Attributes).
        public uint CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetFinalPathNameByHandleW(SafeFileHandle file, char* path, uint length, uint flags);
}
