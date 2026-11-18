using Tiresias.Agent;

namespace Tiresias.Keyring;

/// <summary>
/// When the Tiresias app runs, it is the agent for this session: <c>tir</c> asks it for consent,
/// unlocks and locks through it, rather than opening a second Hello session and lease of its own.
/// Without the app, every call here reports that and the command carries on in the terminal.
/// </summary>
static class AppLink
{
    /// <summary>
    /// Long enough for the user to answer, plus requests queued ahead of this one; the app denies a
    /// dialog nobody answers well before this.
    /// </summary>
    static readonly TimeSpan ConsentWait = TimeSpan.FromMinutes(10);

    /// <returns>The app's state line, or <c>null</c> when it isn't running.</returns>
    public static async Task<string?> StateAsync() => (await PingAsync())?.State;

    /// <returns>The app's state and build, or <c>null</c> when it isn't running.</returns>
    public static Task<ControlReply?> PingAsync() => TryAsync(new(ControlRequest.Ping));

    /// <summary>Asks for approval of what <paramref name="lines"/> describe: in the app's dialog when it runs, otherwise here.</summary>
    /// <param name="lines">Already printed by the caller; the app shows them in its dialog.</param>
    public static async Task<bool> ApproveAsync(string title, IReadOnlyList<string> lines)
    {
        ControlReply? reply;
        try
        {
            if (await StateAsync() is not null)
                Console.WriteLine("Waiting for your answer in the Tiresias app...");
            reply = await TryAsync(new(ControlRequest.Consent, lines, title), ConsentWait);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("No answer came from the Tiresias app, so this was not approved.");
            return false;
        }
        if (reply is { Ok: true })
        {
            Console.WriteLine(reply.Approved ? "Approved in the Tiresias app." : "Denied in the Tiresias app.");
            return reply.Approved;
        }
        if (reply?.Message is { } message)
            Console.Error.WriteLine($"The Tiresias app couldn't ask: {message} Asking here instead.");
        return Terminal.Confirm("Approve?");
    }

    /// <returns>The app's reply to unlock or lock, or <c>null</c> when it isn't running.</returns>
    public static Task<ControlReply?> SendAsync(string op) =>
        // An unlock may wait for the user at the Windows Hello prompt.
        TryAsync(new(op), TimeSpan.FromMinutes(3));

    /// <summary>The app being absent, or going away mid-call, both read as "not running".</summary>
    static async Task<ControlReply?> TryAsync(ControlRequest request, TimeSpan? wait = null)
    {
        try
        {
            return await ControlClient.TryAsync(request, wait);
        }
        catch (IOException)
        {
            return null;
        }
    }
}
