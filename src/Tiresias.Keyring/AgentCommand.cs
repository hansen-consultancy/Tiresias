using Tiresias.Agent;
using Tiresias.UserSecrets;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir agent</c>: the agent in a terminal, for when the tray app isn't running. It unlocks with
/// Windows Hello on start, serves user secrets with consent asked here, and keeps the lease alive.
/// The terminal is read by one loop only; a consent question borrows the next line typed.
/// </summary>
static class AgentCommand
{
    public static async Task<int> RunAsync()
    {
        if (await ControlClient.TryAsync(new(ControlRequest.Ping)) is not null)
        {
            Console.Error.WriteLine("The Tiresias app is already running and is the agent for this session. Use its tray icon, or quit it first.");
            return 1;
        }

        var prompt = new TerminalConsent();
        await using var host = new AgentHost(prompt);
        host.Log += Log;
        try
        {
            await host.StartAsync();
        }
        catch (IOException)
        {
            Console.Error.WriteLine("Another Tiresias agent is already running in this session (another terminal running tir agent?).");
            return 1;
        }

        await UnlockAsync(host);
        Log("Agent running. Type u + Enter to unlock, l to lock, q to quit. Quitting leaves the lease open until it times out or you run tir lock.");
        while (Console.ReadLine() is { } line)
        {
            if (prompt.TryAnswer(line))
                continue;
            switch (line.Trim().ToLowerInvariant())
            {
                case "u":
                    await UnlockAsync(host);
                    break;
                case "l":
                    await host.LockAsync();
                    break;
                case "q":
                    return 0;
            }
        }
        return 0;
    }

    static async Task UnlockAsync(AgentHost host)
    {
        Log("Unlocking: confirm with Windows Hello.");
        try
        {
            var result = await host.UnlockAsync();
            Log(result is { Ok: false } ? $"User secrets unlocked, but the lease didn't open: {result.Message}" : "Unlocked.");
        }
        catch (Exception e) when (e is InvalidOperationException or HttpRequestException)
        {
            Log($"Still locked: {e.Message}");
        }
    }

    static void Log(string message) => Console.WriteLine($"{DateTime.Now:HH:mm:ss} {message}");

    /// <summary>Asks in the terminal; the main loop hands it the next line typed.</summary>
    sealed class TerminalConsent : IUserSecretsConsentPrompt
    {
        TaskCompletionSource<string>? pending;

        public bool TryAnswer(string line) => Interlocked.Exchange(ref pending, null)?.TrySetResult(line) == true;

        public async Task<ConsentAnswer> AskAsync(UserSecretsConsentRequest request, CancellationToken ct)
        {
            var answer = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            pending = answer;
            Console.WriteLine();
            Console.WriteLine("A program asks for user secrets (values are never shown):");
            foreach (var line in request.Describe())
                Console.WriteLine("  " + line);
            Console.Write("Allow? [o]nce, for this [s]ession, or [N]o: ");
            try
            {
                return (await answer.Task.WaitAsync(ct)).Trim().ToLowerInvariant() switch
                {
                    "o" or "once" => ConsentAnswer.AllowOnce,
                    "s" or "session" => ConsentAnswer.AllowForSession,
                    _ => ConsentAnswer.Deny,
                };
            }
            catch (OperationCanceledException)
            {
                Interlocked.CompareExchange(ref pending, null, answer);
                Console.WriteLine();
                Log("Consent question withdrawn (timed out or locked).");
                throw;
            }
        }
    }
}
