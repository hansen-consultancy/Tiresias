using System.IO.Pipes;
using Tiresias.Protocol;

namespace Tiresias.Extensions.Configuration;

/// <summary>The app's side of the conversation with the agent.</summary>
public interface IUserSecretsAgent
{
    /// <param name="wait">How long to wait for an agent to start listening.</param>
    /// <returns>The agent's reply, or <c>null</c> when no agent listened within <paramref name="wait"/>.</returns>
    AgentReply? TryLoad(AgentRequest request, TimeSpan wait);
}

/// <param name="pipeName">The agent's pipe; tests pass their own so they never meet a real agent.</param>
sealed class NamedPipeUserSecretsAgent(string? pipeName = null) : IUserSecretsAgent
{
    /// <summary>Long: the reply waits for the user to read a consent screen and touch Hello.</summary>
    static readonly TimeSpan ReplyTimeout = TimeSpan.FromMinutes(5);

    public AgentReply? TryLoad(AgentRequest request, TimeSpan wait)
    {
        using var pipe = new NamedPipeClientStream(".", pipeName ?? AgentWire.PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            pipe.Connect(wait); // Keeps retrying while the pipe doesn't exist yet.
        }
        catch (TimeoutException)
        {
            return null;
        }

        // Configuration loading is synchronous; this runs once at startup.
        using var cts = new CancellationTokenSource(ReplyTimeout);
        return Task.Run(async () =>
        {
            await AgentWire.WriteAsync(pipe, request, cts.Token).ConfigureAwait(false);
            return await AgentWire.ReadAsync<AgentReply>(pipe, cts.Token).ConfigureAwait(false);
        }).GetAwaiter().GetResult();
    }
}
