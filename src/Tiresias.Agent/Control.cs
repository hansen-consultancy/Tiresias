using System.IO.Pipes;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>
/// What <c>tir</c> asks the running tray app, over the agent's control pipe (same framing as
/// <see cref="AgentWire"/>, its own per-user pipe). Version 1.
/// </summary>
/// <param name="Lines">For <see cref="Consent"/>: the consent lines to show, as <c>tir</c> would print them.</param>
/// <param name="Title">For <see cref="Consent"/>: what is being approved, e.g. <c>tir exec gh</c>.</param>
public sealed record ControlRequest(string Op, IReadOnlyList<string>? Lines = null, string? Title = null, int V = ControlRequest.Version)
{
    public const int Version = 1;
    public const string Ping = "ping";
    public const string Consent = "consent";
    public const string Unlock = "unlock";
    public const string Lock = "lock";
}

/// <param name="Approved">For a consent: the user allowed it.</param>
/// <param name="State">A one-line description of the agent's state, for <c>tir status</c>.</param>
public sealed record ControlReply(bool Ok, string? Message = null, bool Approved = false, string? State = null);

/// <summary><c>tir</c>'s side of the control pipe.</summary>
public static class ControlClient
{
    public static string PipeName => $"tiresias.agent.{Environment.UserName}";

    /// <summary>Short: an absent app is normal and must not slow the CLI down.</summary>
    static readonly TimeSpan ConnectTimeout = TimeSpan.FromMilliseconds(300);

    /// <returns>The app's reply, or <c>null</c> when the app isn't running.</returns>
    /// <param name="replyTimeout">How long to wait for the answer: long for a consent, which waits for the user.</param>
    public static async Task<ControlReply?> TryAsync(ControlRequest request, TimeSpan? replyTimeout = null)
    {
        await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try
        {
            await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds);
        }
        catch (TimeoutException)
        {
            return null;
        }
        using var cts = new CancellationTokenSource(replyTimeout ?? TimeSpan.FromSeconds(30));
        await AgentWire.WriteAsync(pipe, request, cts.Token);
        return await AgentWire.ReadAsync<ControlReply>(pipe, cts.Token);
    }
}
