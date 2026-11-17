using System.Net;
using Microsoft.Win32;

namespace Tiresias.Agent;

/// <summary>
/// Keeps the open lease alive with a heartbeat every five minutes, and ends it the moment the
/// workstation locks, logs off or suspends. <c>tir agent</c> runs it in a terminal; the tray app runs
/// it in the background. If it dies, the broker still ends the lease once the heartbeat has been
/// missing for its timeout.
/// </summary>
public sealed class LeaseKeeper : IDisposable
{
    static readonly TimeSpan HeartbeatPeriod = TimeSpan.FromMinutes(5);

    readonly SemaphoreSlim gate = new(1, 1);

    /// <summary>One line per event worth telling the user about. Never carries a secret.</summary>
    public event Action<string>? Log;

    /// <summary>
    /// The workstation locked, slept or logged off, or the broker says the lease is gone. Raised
    /// before the broker is told, on the thread that noticed; handlers lock whatever they hold.
    /// </summary>
    public event Action<string>? Locked;

    /// <summary>Runs until <paramref name="stop"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken stop)
    {
        // SystemEvents raises these on its own message-loop thread; block it until the broker has
        // heard, so a suspend doesn't outrun the revoke.
        SessionSwitchEventHandler onSwitch = (_, e) =>
        {
            if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff)
                EndAsync(e.Reason.ToString()).GetAwaiter().GetResult();
        };
        PowerModeChangedEventHandler onPower = (_, e) =>
        {
            if (e.Mode == PowerModes.Suspend)
                EndAsync("Suspend").GetAwaiter().GetResult();
        };
        SystemEvents.SessionSwitch += onSwitch;
        SystemEvents.PowerModeChanged += onPower;

        try
        {
            using var timer = new PeriodicTimer(HeartbeatPeriod);
            do
                await HeartbeatAsync();
            while (await timer.WaitForNextTickAsync(stop));
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            SystemEvents.SessionSwitch -= onSwitch;
            SystemEvents.PowerModeChanged -= onPower;
        }
    }

    async Task HeartbeatAsync()
    {
        await gate.WaitAsync();
        try
        {
            if (KeyringStore.Lease is not { } lease || KeyringStore.Broker is not { } broker)
                return;
            using var client = BrokerClient.For(broker);
            var response = await client.PostAsync("/lease/heartbeat", new { lease.LeaseId });
            if (response.Ok)
                return;
            if (response.Status is HttpStatusCode.ServiceUnavailable or HttpStatusCode.Conflict)
            {
                KeyringStore.Lease = null;
                Say($"Lease {lease.LeaseId} has ended ({response.Describe()}). Unlock again for a new one.");
                Locked?.Invoke("lease ended");
            }
            else
                Say($"Heartbeat refused: {response.Describe()}");
        }
        catch (HttpRequestException ex)
        {
            Say($"Heartbeat failed: {ex.Message}");
        }
        finally
        {
            gate.Release();
        }
    }

    async Task EndAsync(string reason)
    {
        await gate.WaitAsync();
        try
        {
            Locked?.Invoke(reason);
            if (KeyringStore.Lease is not { } lease || KeyringStore.Broker is not { } broker)
                return;
            using var client = BrokerClient.For(broker);
            var response = await client.PostAsync("/lease/end");
            KeyringStore.Lease = null;
            Say(response.Ok ? $"{reason}: lease {lease.LeaseId} ended." : $"{reason}: broker refused the revoke ({response.Describe()}).");
        }
        catch (HttpRequestException ex)
        {
            Say($"{reason}: could not reach the broker ({ex.Message}); the lease ends when its heartbeat times out.");
        }
        finally
        {
            gate.Release();
        }
    }

    void Say(string message) => Log?.Invoke(message);

    public void Dispose() => gate.Dispose();
}
