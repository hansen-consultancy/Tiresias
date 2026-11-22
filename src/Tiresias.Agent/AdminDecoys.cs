using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Tiresias.AdminTier;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>
/// The decoys when the admin tier holds them (docs/admin-tier.md, <i>Decoys held by the service</i>).
/// The agent still places them, as the user; then the service takes the set and <c>decoys.json</c>
/// goes, so the agent stops listening and the service listens instead. Getting the set back takes an
/// elevated process, which writes it to the user's <c>decoys.json</c> again; the agent then removes
/// the decoys as it always has.
/// </summary>
public static partial class AdminDecoys
{
    /// <summary>Places a decoy locally. Passing the set to the service requires a separate enrollment.</summary>
    /// <exception cref="InvalidOperationException">Something is already at that place, or the admin tier holds this user's decoys.</exception>
    public static PlacedDecoy Place(DecoyKind kind, string? where)
    {
        if (AdminClient.Installed && Status() is { Held: true })
            throw new InvalidOperationException("The admin tier holds your decoys, so no other set can be placed beside them. Remove them first (tir decoys remove), then place again.");
        return DecoyStore.Place(kind, where);
    }

    /// <summary>
    /// Hands <c>decoys.json</c>'s set to the admin tier and deletes the file, when the tier runs. Kept
    /// as it is when the tier isn't there or refuses: the agent then listens, as without it.
    /// </summary>
    /// <returns>The elevated setup result.</returns>
    public static AdminSetupResult Adopt() => DecoyEnrollment.Run((sid, set) =>
        Send(AdminOps.DecoysAdopt, AdminArgs.Adopt(set, sid))?.ResultAs<AdminDecoysStatus>() is { Held: true, Verified: true });

    /// <summary>The held set's kinds and file count; <c>null</c> when the admin tier doesn't answer.</summary>
    public static AdminDecoysStatus? Status() => Send(AdminOps.DecoysStatus)?.ResultAs<AdminDecoysStatus>()?.ConfirmedStatus();

    /// <summary>
    /// Run elevated (<c>tir decoys release</c>, <c>Tiresias.exe --admin-tier release-decoys</c>):
    /// takes the session user's set back from the admin tier and writes it to that user's
    /// <c>decoys.json</c>. The service keeps its original registration until the local file is durable.
    /// </summary>
    public static AdminSetupResult Release()
    {
        if (Send(AdminOps.DecoysRelease)?.ResultAs<AdminDecoysRelease>() is not { } released)
            return AdminSetupResult.Failed;
        if (released.Set is not { } set)
            return AdminSetupResult.Done;
        if (released.Receipt is not { } receipt)
            return AdminSetupResult.Failed;
        return DecoyEnrollment.WithDesktop((token, sid, path) =>
        {
            if (sid != released.UserSid)
                return AdminSetupResult.Failed;
            using var file = WindowsIdentity.RunImpersonated(token, () => OpenHandBack(path, set));
            return file is not null && Send(AdminOps.DecoysReleaseCommit, new() { ["receipt"] = receipt }) is { Status: AdminStatus.Ok }
                ? AdminSetupResult.Done : AdminSetupResult.Failed;
        });
    }

    /// <summary>
    /// Run elevated by the tier's removal, the service stopped: hands every set in its state folder
    /// back to its user, deleting each one that went.
    /// </summary>
    /// <returns>Whether every set went back; one that didn't stays in the state folder.</returns>
    public static bool HandBackAll(string stateFolder)
    {
        var folder = Path.Combine(stateFolder, "decoys");
        if (!Directory.Exists(folder))
            return true;
        var all = true;
        foreach (var file in Directory.EnumerateFiles(folder, "*.json"))
        {
            var sid = Path.GetFileNameWithoutExtension(file);
            using var restored = AdminArgs.UserSid(sid) && AdminHeldDecoys.Parse(File.ReadAllText(file)) is { } held && KeyringFolder(sid) is { } keyring
                ? OpenHandBack(Path.Combine(keyring, DecoySet.FileName), held.Set) : null;
            if (restored is not null)
                File.Delete(file);
            else
                all = false;
        }
        return all;
    }

    /// <summary>Holds the exact durable file until its service receipt commits. A retry accepts the identical file.</summary>
    static IDisposable? OpenHandBack(string path, DecoySet set)
    {
        var json = set.ToJson();
        var file = CreateFileW(path, GenericWrite | Delete, 0, IntPtr.Zero, CreateNew, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (file.IsInvalid)
        {
            var exists = Marshal.GetLastPInvokeError() is 80 or 183;
            file.Dispose();
            if (!exists)
                return null;
            var existing = SourceHandle.Open(path, directory: false);
            try
            {
                if (existing.ReadText(path, Encoding.UTF8.GetByteCount(json)) == json)
                    return existing;
            }
            catch
            {
                existing.Dispose();
                throw;
            }
            existing.Dispose();
            return null;
        }
        var stream = new FileStream(file, FileAccess.Write);
        try
        {
            if (FinalPath(file) is { } final && AdminHandBack.IsWhereAsked(path, final))
            {
                stream.Write(Encoding.UTF8.GetBytes(json));
                stream.Flush(flushToDisk: true);
                return stream;
            }
        }
        catch
        {
            DiscardNew();
            throw;
        }
        DiscardNew();
        return null;

        void DiscardNew()
        {
            var delete = new FileDispositionInfo { DeleteFile = 1 };
            SetFileInformationByHandle(file, FileDispositionInfoClass, ref delete, (uint)Marshal.SizeOf<FileDispositionInfo>());
            stream.Dispose();
        }
    }

    /// <summary>The default keyring location for an offline user during service removal.</summary>
    static string? KeyringFolder(string sid)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        return key?.GetValue("ProfileImagePath") is string profile ? AdminHandBack.KeyringFolder(Environment.ExpandEnvironmentVariables(profile)) : null;
    }

    static unsafe string? FinalPath(SafeFileHandle file)
    {
        var buffer = new char[1024];
        uint length;
        fixed (char* p = buffer)
            length = GetFinalPathNameByHandleW(file, p, (uint)buffer.Length, 0);
        return length == 0 || length >= buffer.Length ? null : new string(buffer, 0, (int)length);
    }

    static AdminReply? Send(string op, JsonObject? args = null) =>
        // On the thread pool: the app calls this from its UI thread, and it waits on a pipe.
        Task.Run(() => AdminClient.SendAsync(op, args)).GetAwaiter().GetResult();

    const uint GenericWrite = 0x40000000;
    const uint Delete = 0x00010000;
    const uint CreateNew = 1;
    const uint FileFlagOpenReparsePoint = 0x00200000;
    const int FileDispositionInfoClass = 4;

    [StructLayout(LayoutKind.Sequential)]
    struct FileDispositionInfo
    {
        public byte DeleteFile;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial uint GetFinalPathNameByHandleW(SafeFileHandle file, char* path, uint length, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref FileDispositionInfo info, uint size);
}
