using System.Net;
using Microsoft.Win32;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir agent</c>: keeps the open lease alive with a heartbeat every five minutes, and ends it the
/// moment the workstation locks, logs off or suspends. A plain console loop; run it in a terminal
/// or at logon. If it dies, the broker still ends the lease once the heartbeat has been missing
/// for its timeout.
/// </summary>
static class Agent
{
    static readonly TimeSpan HeartbeatPeriod = TimeSpan.FromMinutes(5);

    public static async Task<int> RunAsync()
    {
        using var client = Commands.Client(KeyringStore.RequireBroker(), KeyringStore.Settings);
        using var gate = new SemaphoreSlim(1, 1);
        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stop.Cancel();
        };

        // SystemEvents raises these on its own message-loop thread; block it until the broker has
        // heard, so a suspend doesn't outrun the revoke.
        SessionSwitchEventHandler onSwitch = (_, e) =>
        {
            if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff)
                EndAsync(client, gate, e.Reason.ToString()).GetAwaiter().GetResult();
        };
        PowerModeChangedEventHandler onPower = (_, e) =>
        {
            if (e.Mode == PowerModes.Suspend)
                EndAsync(client, gate, "Suspend").GetAwaiter().GetResult();
        };
        SystemEvents.SessionSwitch += onSwitch;
        SystemEvents.PowerModeChanged += onPower;
        Log("Agent running. Ctrl+C to stop (the lease stays open until it times out or you run tir lock).");

        try
        {
            using var timer = new PeriodicTimer(HeartbeatPeriod);
            do
                await HeartbeatAsync(client, gate);
            while (await timer.WaitForNextTickAsync(stop.Token));
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            SystemEvents.SessionSwitch -= onSwitch;
            SystemEvents.PowerModeChanged -= onPower;
        }
        return 0;
    }

    static async Task HeartbeatAsync(BrokerClient client, SemaphoreSlim gate)
    {
        await gate.WaitAsync();
        try
        {
            if (KeyringStore.Lease is not { } lease)
                return;
            var response = await client.PostAsync("/lease/heartbeat", new { lease.LeaseId });
            if (response.Ok)
                return;
            if (response.Status is HttpStatusCode.ServiceUnavailable or HttpStatusCode.Conflict)
            {
                KeyringStore.Lease = null;
                Log($"Lease {lease.LeaseId} has ended ({response.Describe()}). Run tir unlock for a new one.");
            }
            else
                Log($"Heartbeat refused: {response.Describe()}");
        }
        catch (HttpRequestException ex)
        {
            Log($"Heartbeat failed: {ex.Message}");
        }
        finally
        {
            gate.Release();
        }
    }

    static async Task EndAsync(BrokerClient client, SemaphoreSlim gate, string reason)
    {
        await gate.WaitAsync();
        try
        {
            if (KeyringStore.Lease is not { } lease)
                return;
            var response = await client.PostAsync("/lease/end");
            KeyringStore.Lease = null;
            Log(response.Ok ? $"{reason}: lease {lease.LeaseId} ended." : $"{reason}: broker refused the revoke ({response.Describe()}).");
        }
        catch (HttpRequestException ex)
        {
            Log($"{reason}: could not reach the broker ({ex.Message}); the lease ends when its heartbeat times out.");
        }
        finally
        {
            gate.Release();
        }
    }

    static void Log(string message) => Console.WriteLine($"{DateTime.Now:HH:mm:ss} {message}");
}
