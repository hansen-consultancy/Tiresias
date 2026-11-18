using System.IO.Pipes;
using Tiresias.Protocol;

namespace Tiresias.Extensions.Configuration;

/// <summary>The app's side of the conversation with the agent.</summary>
public interface IUserSecretsAgent
{
    /// <returns>The agent's reply, or <c>null</c> when no agent is listening.</returns>
    AgentReply? TryLoad(AgentRequest request);
}

/// <param name="pipeName">The agent's pipe; tests pass their own so they never meet a real agent.</param>
sealed class NamedPipeUserSecretsAgent(string? pipeName = null) : IUserSecretsAgent
{
    /// <summary>Short: an absent agent is the normal case on a colleague's machine and must not slow startup.</summary>
    static readonly TimeSpan ConnectTimeout = TimeSpan.FromMilliseconds(300);

    /// <summary>Long: the reply waits for the user to read a consent screen and touch Hello.</summary>
    static readonly TimeSpan ReplyTimeout = TimeSpan.FromMinutes(5);

    public AgentReply? TryLoad(AgentRequest request)
    {
        using var pipe = new NamedPipeClientStream(".", pipeName ?? AgentWire.PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            pipe.Connect(ConnectTimeout);
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
