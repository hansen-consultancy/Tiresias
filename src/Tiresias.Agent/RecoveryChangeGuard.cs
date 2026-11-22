using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Tiresias.Agent;

/// <summary>Gives the initiating desktop process one chance to veto its own unused-key replacement.</summary>
internal sealed partial class RecoveryChangeGuard : IDisposable
{
    readonly NamedPipeServerStream pipe;
    internal string Name { get; } = Guid.NewGuid().ToString("D");

    internal RecoveryChangeGuard()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new UnauthorizedAccessException("The desktop account could not be identified.");
        var security = new PipeSecurity();
        security.SetOwner(owner);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.Read | PipeAccessRights.Synchronize, AccessControlType.Allow));
        pipe = NamedPipeServerStreamAcl.Create(PipeName(Name), PipeDirection.Out, 1, PipeTransmissionMode.Byte,
            PipeOptions.FirstPipeInstance | PipeOptions.Asynchronous, 0, 1, security);
    }

    internal void Wait(Process helper, Func<bool> isStillUnused) => WaitAsync(helper, isStillUnused).GetAwaiter().GetResult();

    async Task WaitAsync(Process helper, Func<bool> isStillUnused)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var exited = helper.WaitForExitAsync(deadline.Token);
        var connected = pipe.WaitForConnectionAsync(deadline.Token);
        try
        {
            // The administrator may dismiss the review without requesting a vote.
            if (await Task.WhenAny(connected, exited).ConfigureAwait(false) == connected)
            {
                await connected.ConfigureAwait(false);
                if (helper.HasExited || PipeCaller.Client(pipe).ProcessId != helper.Id)
                    throw new UnauthorizedAccessException("The recovery helper could not be identified.");
                var allowed = await Task.Run(isStillUnused, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                await pipe.WriteAsync(new byte[] { allowed ? (byte)1 : (byte)0 }, deadline.Token).ConfigureAwait(false);
            }
            await exited.ConfigureAwait(false);
        }
        finally
        {
            deadline.Cancel();
        }
    }

    public void Dispose() => pipe.Dispose();
}
