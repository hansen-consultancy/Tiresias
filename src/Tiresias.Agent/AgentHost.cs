using Tiresias.Audit;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.Agent;

/// <summary>
/// The agent of one user session: the unlocked keys, the user-secrets pipe and the lease keeper,
/// started and stopped together. <c>tir agent</c> hosts one in a terminal, the tray app in the
/// background; the consent prompt is the only thing they supply differently. In solo mode it also
/// hosts the broker (<see cref="SoloBroker"/>).
/// </summary>
public sealed class AgentHost : IAsyncDisposable
{
    readonly CancellationTokenSource stop = new();
    readonly LeaseKeeper keeper = new();
    readonly SoloBroker solo = new();
    readonly AuditLog activity;
    readonly List<Task> running = [];

    public AgentHost(IUserSecretsConsentPrompt prompt)
    {
        System.IO.Directory.CreateDirectory(KeyringStore.Directory);
        activity = new AuditLog(ActivityPath, TimeProvider.System);
        UserSecrets = new UserSecretsService(UserSecretsFiles.Root, Keys, prompt, TimeProvider.System, activity);
        UserSecrets.Log += Say;
        keeper.Log += Say;
        keeper.Locked += reason => Lock(reason);
    }

    /// <summary>The agent's own decisions (user secrets), beside the broker's audit log.</summary>
    public static string ActivityPath => Path.Combine(KeyringStore.Directory, "activity.jsonl");

    public AgentKeys Keys { get; } = new();

    public UserSecretsService UserSecrets { get; }

    /// <summary>One line per event, for a log view or the terminal. Never a value.</summary>
    public event Action<string>? Log;

    /// <summary>Unlocked or locked, the lease opened or ended.</summary>
    public event Action? StateChanged;

    /// <summary>Solo mode: whether the broker this agent hosts is up.</summary>
    public bool SoloBrokerRunning => solo.Running;

    /// <summary>Solo mode: why the broker could not start, until it does.</summary>
    public string? SoloBrokerProblem { get; private set; }

    /// <summary>Starts the user-secrets pipe, the lease keeper and, in solo mode, the broker.</summary>
    /// <exception cref="IOException">Another agent (the app, or <c>tir agent</c>) already runs in this session.</exception>
    public async Task StartAsync()
    {
        var server = new AgentPipeServer<AgentRequest, AgentReply>(AgentWire.PipeName, UserSecrets.HandleAsync, PipeCaller.Identify);
        server.ConnectionFailed += e => Say($"A user-secrets request failed: {e.Message}");
        var serving = server.RunAsync(stop.Token);
        if (serving.IsFaulted)
            await serving;
        running.Add(serving);
        running.Add(keeper.RunAsync(stop.Token));
        await StartSoloBrokerAsync();
    }

    /// <summary>Starts the solo broker when this device uses one and it isn't up; a failure is kept in <see cref="SoloBrokerProblem"/>, not thrown.</summary>
    async Task StartSoloBrokerAsync()
    {
        if (KeyringStore.Tenant is not { Solo: true })
            return;
        try
        {
            if (solo.Running)
                await solo.RefreshAsync();
            else
                await solo.StartAsync();
            SoloBrokerProblem = null;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The broker refuses to start on a trust chain or vault it can't verify; say so rather than crash the agent.
            SoloBrokerProblem = e is IOException ? e.Message : $"The solo broker could not start: {e.Message}";
            Say(SoloBrokerProblem);
        }
        StateChanged?.Invoke();
    }

    /// <summary>
    /// The Windows Hello prompt, then the broker lease when this device is enrolled. User secrets
    /// open from here on; the lease failing does not undo that, and the result says why.
    /// </summary>
    public async Task<UnlockResult?> UnlockAsync()
    {
        await Task.Run(() => Keys.Unlock());
        StateChanged?.Invoke();
        if (KeyringStore.Broker is null)
            return null;
        await StartSoloBrokerAsync();
        if (SoloBrokerProblem is { } problem)
            return new(false, problem, [], [], []);
        var result = await LeaseControl.UnlockAsync(Keys.Hello!);
        Say(result.Message);
        StateChanged?.Invoke();
        return result;
    }

    /// <summary>Forgets the keys and every session consent, and ends the lease when there is one.</summary>
    public async Task LockAsync()
    {
        Lock("locked by you");
        if (KeyringStore.Lease is null || KeyringStore.Broker is null)
            return;
        try
        {
            if (await LeaseControl.LockAsync() is { } refused)
                Say($"The broker refused to end the lease ({refused}); it ends when its heartbeat times out.");
        }
        catch (HttpRequestException e)
        {
            Say($"Could not reach the broker to end the lease ({e.Message}); it ends when its heartbeat times out.");
        }
        StateChanged?.Invoke();
    }

    void Lock(string reason)
    {
        var wasUnlocked = Keys.IsUnlocked;
        Keys.Lock();
        UserSecrets.Lock();
        if (wasUnlocked)
            Say($"Locked: {reason}.");
        StateChanged?.Invoke();
    }

    void Say(string message) => Log?.Invoke(message);

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        try
        {
            await Task.WhenAll(running);
        }
        catch (Exception e) when (e is OperationCanceledException or IOException)
        {
        }
        await solo.DisposeAsync();
        Keys.Dispose();
        UserSecrets.Dispose();
        keeper.Dispose();
        activity.Dispose();
        stop.Dispose();
    }
}
