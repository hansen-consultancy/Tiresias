using System.IO.Pipes;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>
/// What <c>tir</c> asks the running tray app, over the agent's control pipe (same framing as
/// <see cref="AgentWire"/>, its own per-user pipe). Version 1.
/// </summary>
/// <param name="Lines">For <see cref="Consent"/>: the consent lines to show, as <c>tir</c> would print them. For <see cref="Environment"/>: the command line to run.</param>
/// <param name="Title">For <see cref="Consent"/>: what is being approved, e.g. <c>tir exec gh</c>. For <see cref="Environment"/>: the program that will run.</param>
/// <param name="Directory">For <see cref="Environment"/> and <see cref="ShellEnvironment"/>: the working directory, which picks the folder sets.</param>
/// <param name="Shell">For <see cref="ShellEnvironment"/>: the terminal's shell process id. Believed only when it is an ancestor of the caller.</param>
/// <param name="AskAgain">For <see cref="ShellEnvironment"/>: ask even though the user said no in this terminal.</param>
public sealed record ControlRequest(string Op, IReadOnlyList<string>? Lines = null, string? Title = null, int V = ControlRequest.Version,
    string? Directory = null, int? Shell = null, bool AskAgain = false, IReadOnlyList<string>? Names = null)
{
    public const int Version = 1;
    public const string Ping = "ping";
    public const string Consent = "consent";
    public const string Unlock = "unlock";
    public const string Lock = "lock";
    /// <summary>Bring the app's window forward: a second start of the same copy sends this, then exits.</summary>
    public const string Show = "show";
    /// <summary>Quit so another copy (a development build, the installed app) can take over the session.</summary>
    public const string Quit = "quit";
    /// <summary><c>tir run</c>: the sealed environment variables for one process, after the user allows it.</summary>
    public const string Environment = "environment";
    /// <summary>The terminal hook: the sealed variables for a shell and its directory, asked once per shell session.</summary>
    public const string ShellEnvironment = "shell-environment";
    /// <summary>The NuGet credential plugin: <see cref="Title"/> is the source URI, <see cref="AskAgain"/> means the feed refused the last answer.</summary>
    public const string NuGetCredential = "nuget-credential";
}

/// <param name="Approved">For a consent: the user allowed it.</param>
/// <param name="State">A one-line description of the agent's state, for <c>tir status</c>.</param>
/// <param name="Build">For a ping: the app's version, marked when it is a development build. Absent from apps before 0.1.0-preview.5.</param>
/// <param name="Folder">For a ping: where the running app's files are, which tells two copies apart.</param>
/// <param name="Variables">For an environment request the user allowed: the sealed variables, by name.</param>
/// <param name="Username">For a NuGet credential the user allowed: the user name the feed is given.</param>
/// <param name="Password">For a NuGet credential the user allowed: the sealed variable's value.</param>
public sealed record ControlReply(bool Ok, string? Message = null, bool Approved = false, string? State = null, string? Build = null, string? Folder = null,
    IReadOnlyDictionary<string, string>? Variables = null, string? Username = null, string? Password = null);

/// <summary><c>tir</c>'s side of the control pipe.</summary>
public static class ControlClient
{
    public static string PipeName => $"tiresias.agent.{System.Environment.UserName}";

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
        // The app may answer with a consent dialog or a Hello prompt: let it come to the front.
        Foreground.AllowServerOf(pipe.SafePipeHandle);
        using var cts = new CancellationTokenSource(replyTimeout ?? TimeSpan.FromSeconds(30));
        await AgentWire.WriteAsync(pipe, request, cts.Token);
        return await AgentWire.ReadAsync<ControlReply>(pipe, cts.Token);
    }
}
