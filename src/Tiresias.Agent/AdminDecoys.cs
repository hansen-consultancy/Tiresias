using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Tiresias.Admin;
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
    /// <summary>Places a decoy as <see cref="DecoyStore.Place"/> does, then hands the set to the admin tier when it runs.</summary>
    /// <exception cref="InvalidOperationException">Something is already at that place, or the admin tier holds this user's decoys.</exception>
    public static PlacedDecoy Place(DecoyKind kind, string? where)
    {
        if (DecoyStore.Current is null && Status() is { Held: true })
            throw new InvalidOperationException("The admin tier holds your decoys, so no other set can be placed beside them. Remove them first (tir decoys remove), then place again.");
        var placed = DecoyStore.Place(kind, where);
        Adopt();
        return placed;
    }

    /// <summary>
    /// Hands <c>decoys.json</c>'s set to the admin tier and deletes the file, when the tier runs. Kept
    /// as it is when the tier isn't there or refuses: the agent then listens, as without it.
    /// </summary>
    /// <returns>Whether the admin tier holds the set now.</returns>
    public static bool Adopt()
    {
        if (DecoyStore.Current is not { Placed.Count: > 0 } set)
            return false;
        if (Send(AdminOps.DecoysAdopt, AdminArgs.Adopt(set)) is not { Status: AdminStatus.Ok })
            return false;
        File.Delete(DecoyStore.FilePath);
        return true;
    }

    /// <summary>The held set's kinds and file count; <c>null</c> when the admin tier doesn't answer.</summary>
    public static AdminDecoysStatus? Status() => Send(AdminOps.DecoysStatus)?.ResultAs<AdminDecoysStatus>();

    /// <summary>The decoy uses queued for this user, after acknowledging <paramref name="ack"/>; <c>null</c> when the admin tier doesn't answer.</summary>
    public static async Task<IReadOnlyList<AdminEvent>?> WaitAsync(IReadOnlyList<long> ack, CancellationToken ct)
    {
        var args = new JsonObject { ["ack"] = AdminWire.ToNode(ack.ToArray()), ["wait"] = AdminWire.MaxWaitSeconds };
        var reply = await AdminClient.SendAsync(AdminOps.EventsWait, args, TimeSpan.FromSeconds(AdminWire.MaxWaitSeconds + 10), ct);
        return reply?.ResultAs<AdminEvents>()?.Events;
    }

    /// <summary>
    /// For the app's <i>This wasn't me</i>: asks the admin tier to freeze the process and block its
    /// program's network, as it does on a decoy use.
    /// </summary>
    /// <returns>What it did; <c>null</c> when it doesn't answer or refuses.</returns>
    public static async Task<AdminFreezeResult?> FreezeAsync(int processId) =>
        (await AdminClient.SendAsync(AdminOps.Freeze, new JsonObject { ["pid"] = processId }))?.ResultAs<AdminFreezeResult>();

    /// <summary>Run elevated (<c>Tiresias.exe --admin-tier thaw &lt;program&gt;</c>): thaws the session user's freezes of the program and unblocks its network.</summary>
    public static AdminSetupResult Thaw(string program) =>
        Send(AdminOps.Thaw, new JsonObject { ["program"] = program }) is { Status: AdminStatus.Ok } ? AdminSetupResult.Done : AdminSetupResult.Failed;

    /// <summary>Run elevated by the tier's removal: asks the running service to undo its work (<see cref="AdminInstallStep.Teardown"/>).</summary>
    /// <returns>Whether it answered that it did.</returns>
    public static bool Teardown() => Send(AdminOps.Teardown) is { Status: AdminStatus.Ok };

    /// <summary>
    /// Run elevated (<c>tir decoys release</c>,<c>Tiresias.exe --admin-tier release-decoys</c>):
    /// takes the session user's set back from the admin tier and writes it to that user's
    /// <c>decoys.json</c>. When it can't be written, the set is handed to the admin tier again.
    /// </summary>
    public static AdminSetupResult Release()
    {
        if (Send(AdminOps.DecoysRelease)?.ResultAs<AdminDecoysRelease>() is not { } released)
            return AdminSetupResult.Failed;
        if (released.Set is not { } set)
            return AdminSetupResult.Done;
        if (HandBack(released.UserSid, set))
            return AdminSetupResult.Done;
        Send(AdminOps.DecoysAdopt, AdminArgs.Adopt(set));
        return AdminSetupResult.Failed;
    }

    /// <summary>
    /// Run elevated by the tier's removal, the service stopped: hands every set in its state folder
    /// back to its user, deleting each one that went, and undoes the service's read auditing: the
    /// rules on the sets' files, and File System success auditing once no set is left, if the
    /// service turned it on (<c>audit.json</c>).
    /// </summary>
    /// <returns>Whether every set went back; one that didn't stays in the state folder.</returns>
    public static bool HandBackAll(string stateFolder)
    {
        var folder = Path.Combine(stateFolder, "decoys");
        var all = true;
        var privileged = Privileged();
        foreach (var file in Directory.Exists(folder) ? Directory.EnumerateFiles(folder, "*.json") : [])
        {
            var sid = Path.GetFileNameWithoutExtension(file);
            if (AdminArgs.UserSid(sid) && AdminHeldDecoys.Parse(File.ReadAllText(file)) is { } held && HandBack(sid, held.Set))
            {
                if (privileged)
                    foreach (var path in held.Files)
                        AuditRules.Remove(path);
                File.Delete(file);
            }
            else
                all = false;
        }
        var audit = Path.Combine(stateFolder, "audit.json");
        if (all && privileged && File.Exists(audit) && AdminAuditState.Parse(File.ReadAllText(audit)).Release(0).TurnOff)
        {
            AuditRules.SetSuccess(false);
            File.Delete(audit);
        }
        return all;
    }

    static bool Privileged()
    {
        try
        {
            AuditRules.EnablePrivilege();
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    /// <summary>Writes the set to the user's <c>decoys.json</c>, only as a new file at exactly that path (<see cref="AdminHandBack"/>).</summary>
    static bool HandBack(string sid, DecoySet set)
    {
        if (KeyringFolder(sid) is not { } folder || !Directory.Exists(folder))
            return false;
        var path = Path.Combine(folder, DecoySet.FileName);
        using var file = CreateFileW(path, GenericWrite | Delete, 0, IntPtr.Zero, CreateNew, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (file.IsInvalid)
            return false;
        if (FinalPath(file) is not { } final || !AdminHandBack.IsWhereAsked(path, final))
        {
            // Not where it was asked for: a link on the way. Ours to take back, since it was just made.
            var delete = new FileDispositionInfo { DeleteFile = 1 };
            SetFileInformationByHandle(file, FileDispositionInfoClass, ref delete, (uint)Marshal.SizeOf<FileDispositionInfo>());
            return false;
        }
        using var stream = new FileStream(file, FileAccess.Write);
        stream.Write(Encoding.UTF8.GetBytes(set.ToJson()));
        return true;
    }

    /// <summary>The keyring folder of the user with this SID: this process's own, or the one in their profile.</summary>
    static string? KeyringFolder(string sid)
    {
        if (string.Equals(WindowsIdentity.GetCurrent().User?.Value, sid, StringComparison.OrdinalIgnoreCase))
            return KeyringStore.Directory;
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
