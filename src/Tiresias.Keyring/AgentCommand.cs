using Tiresias.Agent;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir agent</c>: the agent in a terminal, for when the tray app isn't running. A plain console
/// loop; run it in a terminal or at logon.
/// </summary>
static class AgentCommand
{
    public static async Task<int> RunAsync()
    {
        KeyringStore.RequireBroker();
        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stop.Cancel();
        };
        using var keeper = new LeaseKeeper();
        keeper.Log += Log;
        Log("Agent running. Ctrl+C to stop (the lease stays open until it times out or you run tir lock).");
        await keeper.RunAsync(stop.Token);
        return 0;
    }

    static void Log(string message) => Console.WriteLine($"{DateTime.Now:HH:mm:ss} {message}");
}
