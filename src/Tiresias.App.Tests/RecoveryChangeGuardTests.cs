using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using NUnit.Framework;
using Tiresias.Agent;

namespace Tiresias.App.Tests;

public class RecoveryChangeGuardTests
{
    [TestCase(true, 1)]
    [TestCase(false, 0)]
    public void Only_the_launched_helper_receives_the_current_decision(bool allowed, int expectedVote)
    {
        using var guard = new RecoveryChangeGuard();
        using var child = PowerShell($$"""
            $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'tiresias.recovery.{{guard.Name}}', 'In', 'None', 'Anonymous')
            try { $pipe.Connect(10000); exit $pipe.ReadByte() } finally { $pipe.Dispose() }
            """);
        int checks = 0;
        guard.Wait(child, () => { checks++; return allowed; });
        Assert.That(checks, Is.EqualTo(1));
        Assert.That(child.ExitCode, Is.EqualTo(expectedVote));
    }

    [Test]
    public void An_unexpected_client_cannot_trigger_the_desktop_check()
    {
        using var guard = new RecoveryChangeGuard();
        using var child = PowerShell("[Console]::ReadLine() | Out-Null", redirectInput: true);
        try
        {
            using var unexpected = new NamedPipeClientStream(".", "tiresias.recovery." + guard.Name, PipeDirection.In,
                PipeOptions.None, TokenImpersonationLevel.Anonymous);
            unexpected.Connect(10000);
            Assert.That(() => guard.Wait(child, () => throw new AssertionException("Unexpected check")), Throws.TypeOf<UnauthorizedAccessException>());
        }
        finally
        {
            child.StandardInput.Close();
            Assert.That(child.WaitForExit(10000), Is.True);
        }
    }

    [TestCase(1, true)]
    [TestCase(0, false)]
    [TestCase(2, false)]
    [TestCase(-1, false)]
    public async Task The_helper_requires_one_explicit_approval_byte_from_the_expected_server(int vote, bool allowed)
    {
        var nonce = Guid.NewGuid().ToString("D");
        using var server = new NamedPipeServerStream("tiresias.recovery." + nonce, PipeDirection.Out, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
        var check = RecoveryChangeGuard.ConfirmAsync(nonce, System.Environment.ProcessId, TimeSpan.FromSeconds(10));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await server.WaitForConnectionAsync(deadline.Token);
        if (vote >= 0)
            await server.WriteAsync(new[] { (byte)vote }, deadline.Token);
        else
            server.Dispose();
        if (allowed)
            await check;
        else
            Assert.That(async () => await check, Throws.InvalidOperationException.Or.InstanceOf<IOException>());
    }

    [Test]
    public void A_missing_server_and_invalid_pipe_names_cannot_confirm()
    {
        Assert.That(async () => await RecoveryChangeGuard.ConfirmAsync(Guid.NewGuid().ToString("D"), System.Environment.ProcessId, TimeSpan.FromMilliseconds(150)),
            Throws.InstanceOf<OperationCanceledException>());
        Assert.That(() => RecoveryChangeGuard.Confirm("invalid", System.Environment.ProcessId), Throws.InvalidOperationException);
    }

    [Test]
    public void A_different_process_cannot_replace_the_expected_server()
    {
        var nonce = Guid.NewGuid().ToString("D");
        using var child = PowerShell($$"""
            $pipe = [IO.Pipes.NamedPipeServerStream]::new('tiresias.recovery.{{nonce}}', 'Out', 1, 'Byte', 'Asynchronous')
            try {
                [Console]::Out.WriteLine('ready'); [Console]::Out.Flush()
                $wait = $pipe.BeginWaitForConnection($null, $null)
                if ($wait.AsyncWaitHandle.WaitOne(10000)) { $pipe.EndWaitForConnection($wait); $pipe.WriteByte(1) }
            } finally { $pipe.Dispose() }
            """);
        try
        {
            // A cold PowerShell can take longer to start than the connect timeout: connect only once its pipe exists.
            var ready = child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(60)).GetAwaiter().GetResult();
            Assert.That(ready, Is.EqualTo("ready"));
            Assert.That(() => RecoveryChangeGuard.ConfirmAsync(nonce, System.Environment.ProcessId, TimeSpan.FromSeconds(10)),
                Throws.TypeOf<UnauthorizedAccessException>());
        }
        finally { Assert.That(child.WaitForExit(30000), Is.True); }
    }

    static Process PowerShell(string script, bool redirectInput = false)
    {
        var exe = Path.Combine(System.Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = redirectInput, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Command", script })
            start.ArgumentList.Add(arg);
        return Process.Start(start) ?? throw new InvalidOperationException("Could not start the isolated test peer.");
    }
}
