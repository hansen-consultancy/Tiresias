using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Tiresias.AdminTier;

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

    public static SourceHandle Open(string path, bool directory, bool allowDelete = false)
    {
        var flags = FileFlagOpenReparsePoint | (directory ? FileFlagBackupSemantics : 0);
        var access = (directory ? FileReadAttributes : GenericRead) | (allowDelete ? 0x00010000u : 0u);
        var handle = CreateFileW(path, access, FileShareRead, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
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

    /// <summary>Reads a bounded regular file at its expected final path while retaining the handle for the handoff.</summary>
    public string? ReadText(string path, int limit)
    {
        if ((Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 || Links != 1 ||
            !AdminHandBack.IsWhereAsked(path, FinalPath))
            return null;
        var size = RandomAccess.GetLength(Handle);
        if (size > limit)
            return null;
        var bytes = new byte[checked((int)size)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = RandomAccess.Read(Handle, bytes.AsSpan(offset), offset);
            if (read == 0)
                return null;
            offset += read;
        }
        return Encoding.UTF8.GetString(bytes);
    }

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
