using System.IO.Pipes;
using Tiresias.Protocol;

namespace Tiresias.UserSecrets;

/// <summary>
/// The named-pipe end of <see cref="AgentWire"/> framing: accepts any number of connections, reads one
/// request from each, answers it with the handler, and closes. The pipe admits only the current
/// user (<see cref="PipeOptions.CurrentUserOnly"/>), and the caller is identified from the pipe
/// itself, never from anything the client says.
/// </summary>
/// <remarks>The user-secrets pipe speaks <see cref="AgentRequest"/>/<see cref="AgentReply"/>; the agent's control pipe its own pair.</remarks>
public sealed class AgentPipeServer<TRequest, TReply>(
    string pipeName,
    Func<TRequest, string?, CancellationToken, Task<TReply>> handle,
    Func<NamedPipeServerStream, string?> identifyCaller)
{
    /// <summary>A client that connects and then says nothing is dropped after this.</summary>
    static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Raised when one connection fails (the client went away mid-message, say). The server carries on.</summary>
    public event Action<Exception>? ConnectionFailed;

    /// <summary>Serves until <paramref name="stop"/> is cancelled.</summary>
    /// <exception cref="IOException">Another process already serves this pipe (on Windows, where that can be told).</exception>
    public async Task RunAsync(CancellationToken stop)
    {
        var first = true;
        var running = new List<Task>();
        while (!stop.IsCancellationRequested)
        {
            var options = PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly;
            if (first && OperatingSystem.IsWindows())
                options |= PipeOptions.FirstPipeInstance;
            NamedPipeServerStream pipe;
            try
            {
                pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, options);
            }
            catch (Exception e) when (first && e is UnauthorizedAccessException or IOException)
            {
                throw new IOException($"Another process is already serving '{pipeName}'.", e);
            }
            first = false;
            try
            {
                await pipe.WaitForConnectionAsync(stop);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync();
                break;
            }
            running.RemoveAll(t => t.IsCompleted);
            running.Add(ServeAsync(pipe, stop));
        }
        await Task.WhenAll(running);
    }

    async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stop)
    {
        await using (pipe)
        {
            try
            {
                var caller = identifyCaller(pipe);
                TRequest request;
                using (var read = CancellationTokenSource.CreateLinkedTokenSource(stop))
                {
                    read.CancelAfter(RequestTimeout);
                    request = await AgentWire.ReadAsync<TRequest>(pipe, read.Token);
                }
                var reply = await handle(request, caller, stop);
                await AgentWire.WriteAsync(pipe, reply, stop);
            }
            catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException or OperationCanceledException or EndOfStreamException)
            {
                ConnectionFailed?.Invoke(e);
            }
        }
    }
}
