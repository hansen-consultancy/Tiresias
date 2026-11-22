using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using NUnit.Framework;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Audit;
using Tiresias.Client;

namespace Tiresias.App.Tests;

public class RecoveryEnrollmentActivityTests
{
    [TestCase(true, "The Windows UAC prompt was cancelled.")]
    [TestCase(false, "No was selected in the recovery enrollment helper.")]
    public void A_refusal_appears_once_in_denied_activity(bool cancelUac, string reason)
    {
        var path = Path.GetTempFileName();
        try
        {
            Process? Launch()
            {
                if (cancelUac) throw new Win32Exception(1223);
                Assert.That(RecoveryEnrollmentAuthority.Confirmed(7), Is.False);
                return ExitWith((int)RecoveryEnrollmentResult.Declined);
            }

            Assert.Throws<InvalidOperationException>(() => RecoveryEnrollment.RunHelper(Launch, p => p.WaitForExit(), path));
            var history = ActivityHistory.From(File.ReadLines(path), [], BrokerServiceState.NotInstalled, null);
            var rows = ActivityQuery.Filter(history.Entries, new("Recovery key enrollment", ActivityOutcome.Denied), DateTimeOffset.Now);
            Assert.That(rows.Single().Reason, Is.EqualTo(reason));
            Assert.That(AuditLog.Verify(path), Is.Null);
        }
        finally { File.Delete(path); }
    }

    [Test]
    public void Launch_and_dialog_errors_do_not_record_user_decisions()
    {
        var path = Path.GetTempFileName();
        try
        {
            Assert.Throws<InvalidOperationException>(() => RecoveryEnrollmentAuthority.Confirmed(0));
            Assert.Throws<InvalidOperationException>(() => RecoveryEnrollment.RunHelper(() => throw new Win32Exception(5), _ => { }, path));
            Assert.That(RecoveryEnrollment.RunHelper(() => ExitWith(1), p => p.WaitForExit(), path), Is.EqualTo(1));
            Assert.That(File.ReadAllText(path), Is.Empty);
        }
        finally { File.Delete(path); }
    }

    static Process? ExitWith(int code) => Process.Start(new ProcessStartInfo(
        Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/d /c exit {code}") { UseShellExecute = false, CreateNoWindow = true });
}
