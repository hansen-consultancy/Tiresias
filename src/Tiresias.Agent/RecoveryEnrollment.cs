using Tiresias.Audit;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;

namespace Tiresias.Agent;

/// <summary>Reads the account's protected binding and requests changes through the verified recovery helper.</summary>
internal static class RecoveryEnrollment
{
    internal static RecoveryBinding? Current()
    {
#if DEBUG
        if (DemoMode.CurrentUser is { } demo)
        {
            using var state = demo.OpenSubKey("RecoveryEnrollment");
            return RecoveryEnrollmentHistory.Latest(state, DemoSid, protectedStore: false)?.Binding;
        }
#endif
        return RecoveryEnrollmentHistory.Current(UserSid());
    }

    internal static void Change(RecoveryBinding? expected, string publicKey) => Change(expected, publicKey, onlyIfUnused: false);

    internal static void ChangeUnused(RecoveryBinding? expected, string publicKey) => Change(expected, publicKey, onlyIfUnused: true);

    static void Change(RecoveryBinding? expected, string publicKey, bool onlyIfUnused)
    {
        RecoveryRecipient.ValidateKey(publicKey);
        if (Current() != expected)
            throw Changed();
#if DEBUG
        if (DemoMode.CurrentUser is { } demo)
        {
            using var state = demo.CreateSubKey("RecoveryEnrollment");
            RecoveryEnrollmentHistory.Append(state, DemoSid, DemoSid, expected?.Revision, publicKey, protectedStore: false,
                beforePublish: onlyIfUnused ? () =>
                {
                    if (!RecoveryKey.CanReplaceUnused)
                        throw new InvalidOperationException("Existing sealed data or trust enrollment requires its original paper recovery key.");
                } : null);
            return;
        }
#endif
        using var executable = RecoveryHelperImage.Open();
        using var guard = onlyIfUnused ? new RecoveryChangeGuard() : null;
        var start = new ProcessStartInfo(executable.Path) { UseShellExecute = true, Verb = "runas" };
        foreach (var argument in new[] { "recovery", "enroll-recipient", UserSid(), expected?.Revision.ToString("D") ?? "new", publicKey })
            start.ArgumentList.Add(argument);
        if (guard is not null)
        {
            start.ArgumentList.Add("unused");
            start.ArgumentList.Add(guard.Name);
            start.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        }
        var exitCode = RunHelper(() => Process.Start(start), helper =>
        {
            if (guard is not null)
                guard.Wait(helper, () => RecoveryKey.CanReplaceUnused);
            else
                helper.WaitForExit();
        }, AgentHost.RecoveryActivityPath);
        // Once published, the caller must keep the paper even if the helper failed during final flush or exit.
        if (Current() is { } applied && applied.Revision != expected?.Revision && applied.PublicKey == publicKey)
            return;
        if (exitCode != 0)
            throw new InvalidOperationException("Recovery enrollment could not be completed.");
        throw Changed();
    }

    internal static int RunHelper(Func<Process?> launch, Action<Process> wait, string activityPath)
    {
        Process helper;
        try
        {
            helper = launch() ?? throw new InvalidOperationException("Recovery enrollment could not start.");
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            throw Denied(activityPath, "The Windows UAC prompt was cancelled.", e);
        }
        catch (Win32Exception e)
        {
            throw new InvalidOperationException("Recovery enrollment could not be started.", e);
        }
        using var launched = helper;
        try
        {
            wait(helper);
        }
        catch (OperationCanceledException e)
        {
            throw new InvalidOperationException("The recovery enrollment check timed out.", e);
        }
        if (helper.ExitCode == (int)RecoveryEnrollmentResult.Declined)
            throw Denied(activityPath, "No was selected in the recovery enrollment helper.");
        return helper.ExitCode;
    }

    static InvalidOperationException Denied(string path, string reason, Exception? cause = null)
    {
        // The CLI and desktop can both enroll. Serialize their journal writes across this user's sessions.
        using var gate = new Mutex(false, "Tiresias.RecoveryActivity", new NamedWaitHandleOptions { CurrentUserOnly = true, CurrentSessionOnly = false });
        try
        {
            try { if (!gate.WaitOne(TimeSpan.FromSeconds(10))) throw new IOException("Recovery Activity is busy."); }
            catch (AbandonedMutexException) { }
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                using var journal = new AuditLog(path, TimeProvider.System);
                journal.Append(new(AuditKind.Deny, Service: "Recovery key enrollment", Reason: reason));
            }
            finally { gate.ReleaseMutex(); }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new InvalidOperationException(reason + " The denial could not be recorded in Activity.", e);
        }
        return new InvalidOperationException(reason, cause);
    }

    internal static InvalidOperationException Changed() => RecoveryEnrollmentHistory.Changed();

    static string UserSid()
    {
        using var user = WindowsIdentity.GetCurrent();
        return user.User?.Value ?? throw new UnauthorizedAccessException("The Windows account could not be verified.");
    }

#if DEBUG
    const string DemoSid = "S-1-5-21-1-2-3-1001";
#endif
}
