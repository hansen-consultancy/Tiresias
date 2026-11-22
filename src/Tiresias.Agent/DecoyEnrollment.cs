using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Tiresias.AdminTier;
using Tiresias.Decoys;

namespace Tiresias.Agent;

/// <summary>Transfers exactly the desktop user's placed set from their profile to the elevated enrollment operation.</summary>
internal static partial class DecoyEnrollment
{
    const uint ProcessQueryLimitedInformation = 0x1000, TokenQuery = 0x0008, TokenImpersonate = 0x0004, TokenDuplicate = 0x0002;
    const int TokenElevation = 20;

    internal static AdminSetupResult WithDesktop(Func<SafeAccessTokenHandle, string, string, AdminSetupResult> action)
    {
        GetWindowThreadProcessId(GetShellWindow(), out var pid);
        if (pid == 0)
            return AdminSetupResult.Failed;
        using var shell = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (shell.IsInvalid || !OpenProcessToken(shell, TokenQuery | TokenImpersonate | TokenDuplicate, out var token))
            return AdminSetupResult.Failed;
        using (token)
        using (var desktop = new WindowsIdentity(token.DangerousGetHandle()))
        {
            var sid = desktop.User?.Value;
            if (!AdminArgs.UserSid(sid) || !GetTokenInformation(token, TokenElevation, out var elevated, sizeof(uint), out _) || elevated != 0)
                return AdminSetupResult.Failed;
            var localAppData = new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
            Marshal.ThrowExceptionForHR(SHGetKnownFolderPath(in localAppData, 0, token, out var buffer));
            string path;
            try { path = Path.Combine(Marshal.PtrToStringUni(buffer)!, "Tiresias", DecoySet.FileName); }
            finally { Marshal.FreeCoTaskMem(buffer); }
            if (!AdminArgs.FullPath(path))
                return AdminSetupResult.Failed;
            return action(token, sid!, path);
        }
    }

    internal static AdminSetupResult Run(Func<string, DecoySet, bool> enroll) =>
        WithDesktop((token, sid, path) =>
        {
            using var manifest = WindowsIdentity.RunImpersonated(token, () =>
                File.Exists(path) ? SourceHandle.Open(path, directory: false, allowDelete: true) : null);
            var set = manifest is null ? AdminTierSetup.LegacyDecoys(sid)?.Set :
                WindowsIdentity.RunImpersonated(token, () => DecoySet.Parse(manifest.ReadText(path, 64 * 1024)));
            if (set is null || set.Placed.Count > AdminArgs.MaxPlaced || !AdminArgs.Set(AdminArgs.Adopt(set, sid)["set"]))
                return AdminSetupResult.Failed;
            var candidate = new AdminHeldDecoys(set, AdminHeldDecoys.FilesFor(set));
            bool Placed() => WindowsIdentity.RunImpersonated(token, () => candidate.IsPlaced(step => Matches(sid, step)));
            if (!Placed() || !Confirm(candidate) || !Placed())
                return AdminSetupResult.Failed;
            if (!enroll(sid, set))
                return AdminSetupResult.Failed;
            if (manifest is not null)
            {
                // Delete only the already-open, verified manifest following a confirmed durable handoff.
                var disposition = new byte[] { 1 };
                if (!WindowsIdentity.RunImpersonated(token, () => SetFileInformationByHandle(manifest.Handle, 4, disposition, 1)))
                    return AdminSetupResult.Failed;
            }
            return AdminSetupResult.Done;
        });

    static bool Confirm(AdminHeldDecoys candidate)
    {
        IEnumerable<string> targets = candidate.Files;
        if (candidate.Set.Placed.Any(p => p.Kind == DecoyKind.Variables))
            targets = targets.Concat(DecoyPlan.VariableNames);
        var message = "Enable service monitoring for these verified decoy placements?\n\n" + string.Join("\n", targets) +
            $"\n\nHTTP listener: 127.0.0.1:{candidate.Set.HttpPort}\nSQL listener: 127.0.0.1:{candidate.Set.SqlPort}";
        const uint yesNoDefaultNo = 0x0004 | 0x0020 | 0x0100 | 0x2000;
        return MessageBoxW(0, message, "Tiresias — Verify decoy placements", yesNoDefaultNo) == 6;
    }

    static bool Matches(string sid, DecoyStep step)
    {
        if (step is SetDecoyVariable variable)
        {
            using var environment = Registry.Users.OpenSubKey(sid + @"\Environment");
            return environment?.GetValue(variable.Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string == variable.Value;
        }
        var file = (WriteDecoyFile)step;
        if (new DriveInfo(Path.GetPathRoot(file.Path)!).DriveType != DriveType.Fixed)
            return false;
        using var source = SourceHandle.Open(file.Path, directory: false);
        return source.ReadText(file.Path, Encoding.UTF8.GetMaxByteCount(file.Content.Length)) == file.Content;
    }

    [LibraryImport("user32.dll")]
    private static partial nint GetShellWindow();
    [LibraryImport("user32.dll")]
    private static partial uint GetWindowThreadProcessId(nint window, out uint pid);
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int MessageBoxW(nint owner, string text, string caption, uint options);
    [LibraryImport("kernel32.dll")]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, out uint value, int size, out int returned);
    [LibraryImport("shell32.dll")]
    private static partial int SHGetKnownFolderPath(in Guid folder, uint flags, SafeAccessTokenHandle token, out nint path);
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, byte[] value, uint size);
}
