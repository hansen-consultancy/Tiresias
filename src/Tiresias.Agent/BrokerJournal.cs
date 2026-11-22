using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Tiresias.Audit;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>Serves a snapshot to the enrolling Windows account. Clients never open the broker's live file.</summary>
internal sealed class BrokerJournal(AuditLog log, string ownerSid) : BackgroundService
{
    const string PipeName = "tiresias.broker.journal";
    static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    internal static async Task<IReadOnlyList<string>> ReadAsync()
    {
        await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.In, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        using var timeout = new CancellationTokenSource(Timeout);
        await pipe.ConnectAsync(TimeSpan.FromSeconds(2), timeout.Token).ConfigureAwait(false);
        if (!ServicePipeIdentity.Matches(pipe, AdminService.Query(BrokerServiceLayout.Name).ProcessId))
            throw new InvalidDataException("The broker journal service could not be identified.");
        return await AuditSnapshot.ReadAsync(pipe, timeout.Token).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var access = BrokerJournalAccess.For(new SecurityIdentifier(ownerSid), identity.User!);
        NamedPipeServerStream Listen(bool first) => NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.Out, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None), 0, 0, access);

        while (!stop.IsCancellationRequested)
        {
            NamedPipeServerStream? listener = null;
            try
            {
                listener = Listen(first: true);
                while (!stop.IsCancellationRequested)
                {
                    await listener.WaitForConnectionAsync(stop);
                    using var client = listener;
                    listener = Listen(first: false);
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
                    timeout.CancelAfter(Timeout);
                    try
                    {
                        await AuditSnapshot.WriteAsync(log, client, timeout.Token);
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException or OperationCanceledException)
                    {
                        // The client sees an incomplete frame. The broker continues recording decisions.
                    }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // A busy pipe must not interrupt the broker or its audit writer.
                await Task.Delay(TimeSpan.FromSeconds(1), stop);
            }
            finally
            {
                listener?.Dispose();
            }
        }
    }
}
