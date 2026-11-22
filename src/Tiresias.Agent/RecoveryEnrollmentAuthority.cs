using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Tiresias.Client;
using Tiresias.Windows;

namespace Tiresias.Agent;

/// <summary>Publishes one independently confirmed change for the account signed in to this session.</summary>
internal static partial class RecoveryEnrollmentAuthority
{
    internal static void ApplyElevated(string ownerSid, string expectedRevision, string publicKey, bool onlyIfUnused = false,
        Func<bool>? confirmUnused = null)
    {
        using var admin = WindowsIdentity.GetCurrent();
        if (!Environment.UserInteractive || !new WindowsPrincipal(admin).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("An interactive administrator must confirm recovery enrollment.");
        var author = admin.User?.Value;
        if (!RecoveryRecipient.UserSid(ownerSid) || !RecoveryRecipient.UserSid(author))
            throw new UnauthorizedAccessException("Recovery enrollment requires a Windows user account.");
        Guid? expected = expectedRevision == "new" ? null :
            Guid.TryParseExact(expectedRevision, "D", out var id) && id != Guid.Empty ? id : throw RecoveryEnrollmentHistory.Changed();
        RecoveryRecipient.ValidateKey(publicKey);
        using var process = Process.GetCurrentProcess();
        var desktop = process.SessionId > 0 ? WindowsSessionAccount.Find(process.SessionId, requireDomain: true) : null;
        RequireDesktop(ownerSid, desktop?.Sid);
        if (onlyIfUnused && confirmUnused is null)
            throw new InvalidOperationException("The unused recovery enrollment could not be verified.");
        var previous = RecoveryEnrollmentHistory.Current(ownerSid);
        if (previous?.Revision != expected)
            throw RecoveryEnrollmentHistory.Changed();
        if (!Confirm(desktop!.Name, ownerSid, previous, publicKey, onlyIfUnused))
            throw new InvalidOperationException("Recovery enrollment was declined.");
        using var state = RecoveryEnrollmentHistory.Open(ownerSid, create: true)!;
        RecoveryEnrollmentHistory.Append(state, ownerSid, author!, expected, publicKey, protectedStore: true,
            beforePublish: onlyIfUnused ? () =>
            {
                if (confirmUnused?.Invoke() != true)
                    throw new InvalidOperationException("The desktop could not confirm that the recovery enrollment is unused.");
            } : null);
    }

    internal static void RequireDesktop(string ownerSid, string? desktopSid)
    {
        if (!RecoveryRecipient.UserSid(desktopSid) || desktopSid != ownerSid)
            throw new UnauthorizedAccessException("The recovery recipient belongs to another desktop account.");
    }

    static bool Confirm(string account, string sid, RecoveryBinding? previous, string key, bool onlyIfUnused)
    {
        static string Fingerprint(string recipient) => PaperKey.PublicFingerprint(Convert.FromBase64String(recipient));
        var question = previous is null ? "Enroll a paper recovery key" : "Replace the enrolled paper recovery key";
        var old = previous is null ? "" : $"\nCurrent SHA-256 fingerprint:\n{Fingerprint(previous.PublicKey)}\n";
        var unused = onlyIfUnused ? "\nThis request requires an unused setup. No previous paper key was presented.\n" : "";
        var message = $"{question} for {account} ({sid})?\n{unused}{old}\nNew SHA-256 fingerprint:\n{Fingerprint(key)}\n\nNewly sealed secrets will be recoverable with this paper key.";
        const uint yesNoDefaultNo = 0x0004 | 0x0020 | 0x0100 | 0x2000;
        return MessageBoxW(0, message, "Tiresias - Verify recovery recipient", yesNoDefaultNo) == 6;
    }

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int MessageBoxW(nint owner, string text, string caption, uint options);
}
