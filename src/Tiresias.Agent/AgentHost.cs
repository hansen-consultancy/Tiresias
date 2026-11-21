using Tiresias.Audit;
using Tiresias.EnvironmentVariables;
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
    readonly DecoyWatch decoys = new();
    readonly AuditLog activity;
    readonly List<Task> running = [];

    public AgentHost(IUserSecretsConsentPrompt prompt)
    {
        System.IO.Directory.CreateDirectory(KeyringStore.Directory);
        activity = new AuditLog(ActivityPath, TimeProvider.System);
        UserSecrets = new UserSecretsService(UserSecretsFiles.Root, Keys, prompt, TimeProvider.System, activity, new BrokerSecretReferences(Keys));
        UserSecrets.Log += Say;
        keeper.Log += Say;
        keeper.Locked += reason => Lock(reason);
        solo.Log += Say;
        solo.SecretsUnleased = SealIntoLeaseAsync;
        solo.Audited += (record, at) => BrokerAudited?.Invoke(record, at);
        decoys.Log += Say;
        decoys.Touched += touch =>
        {
            activity.Append(touch.Record());
            Say(touch.Hit.Use == Decoys.DecoyUse.Read
                ? $"Decoy file opened: {touch.Sentence}{(touch.Routine is { } routine ? $" (routine: {routine})" : "")}."
                : $"Decoy used: {touch.Sentence}.");
            DecoyTouched?.Invoke(touch);
        };
    }

    /// <summary>The agent's own decisions (user secrets), beside the broker's audit log.</summary>
    public static string ActivityPath => Path.Combine(KeyringStore.Directory, "activity.jsonl");

    public AgentKeys Keys { get; } = new();

    /// <summary>Records the answer to a request for sealed environment variables in the activity log: the names, never a value.</summary>
    public void RecordEnvironment(bool allowed, string program, IEnumerable<string> names, string? process) =>
        activity.Append(EnvironmentRecord(allowed, program, names, process));

    /// <summary>The activity record for an environment hand-over, for <c>tir</c> to write itself when the app isn't running.</summary>
    public static AuditRecord EnvironmentRecord(bool allowed, string program, IEnumerable<string> names, string? process) =>
        new(allowed ? AuditKind.Allow : AuditKind.Deny, Consumer: "environment", Service: program, Reason: string.Join(", ", names), Process: process);

    /// <summary>Records how a NuGet credential request for a mapped feed was answered: program, feed and variable, never the token.</summary>
    public void RecordNuGet(NuGetOutcome outcome, string program, int processId, string source, string variable) =>
        activity.Append(NuGetActivity.Record(outcome, program, processId, source, variable));

    /// <summary>
    /// Records "This wasn't me" in the activity log: what was asked, the program and the processes
    /// that started it (nearest first), and whether it is now blocked. Never a value.
    /// </summary>
    public void RecordIncident(string asked, string? process, IEnumerable<string> parents, bool blocked) =>
        activity.Append(new(AuditKind.Deny, Consumer: "incident", Service: asked, Process: process,
            Reason: $"This wasn't me: locked{(blocked ? ", program blocked" : "")}; started by {(parents.Any() ? string.Join(" < ", parents) : "unknown")}"));

    public UserSecretsService UserSecrets { get; }

    /// <summary>One line per event, for a log view or the terminal. Never a value.</summary>
    public event Action<string>? Log;

    /// <summary>Unlocked or locked, the lease opened or ended.</summary>
    public event Action? StateChanged;

    /// <summary>
    /// A decoy credential was used, after it is in the activity log. Raised on a pool thread; the
    /// app blocks the program and raises a finding, <c>tir agent</c> only prints it.
    /// </summary>
    public event Action<DecoyTouch>? DecoyTouched;

    /// <summary>Solo mode: a record the broker this agent hosts wrote to its audit log, on the broker's thread. A handler must not throw.</summary>
    public event Action<AuditRecord, DateTimeOffset>? BrokerAudited;

    /// <summary>Whether the decoys' listeners are up (decoys are placed and their ports were free).</summary>
    public bool DecoysListening => decoys.Listening;

    /// <summary>Solo mode: whether the broker this agent hosts is up.</summary>
    public bool SoloBrokerRunning => solo.Running;

    /// <summary>Solo mode: why the broker could not start, until it does.</summary>
    public string? SoloBrokerProblem { get; private set; }

    /// <summary>Starts the user-secrets pipe, the lease keeper and, in solo mode, the broker.</summary>
    /// <exception cref="IOException">Another agent (the app, or <c>tir agent</c>) already runs in this session.</exception>
    public async Task StartAsync()
    {
        var server = new AgentPipeServer<AgentRequest, AgentReply, string?>(AgentWire.PipeName, HandleUserSecretsAsync, PipeCaller.Identify);
        server.ConnectionFailed += e => Say($"A user-secrets request failed: {e.Message}");
        var serving = server.RunAsync(stop.Token);
        if (serving.IsFaulted)
            await serving;
        running.Add(serving);
        running.Add(keeper.RunAsync(stop.Token));
        decoys.Start();
        await StartSoloBrokerAsync();
    }

    /// <summary>Answers the request, then links its id to the asking program's project, off the pipe's path.</summary>
    async Task<AgentReply> HandleUserSecretsAsync(AgentRequest request, string? caller, CancellationToken ct)
    {
        var reply = await UserSecrets.HandleAsync(request, caller, ct);
        _ = Task.Run(() => ProjectIndexStore.LinkFromCaller(caller, request.UserSecretsId), CancellationToken.None);
        return reply;
    }

    /// <summary>Starts the solo broker when this device uses one and it isn't up; a failure is kept in <see cref="SoloBrokerProblem"/>, not thrown.</summary>
    async Task StartSoloBrokerAsync()
    {
        if (KeyringStore.Tenant is not { Solo: true })
            return;
        try
        {
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

    /// <summary>Solo mode: seals secrets added to the vault since the unlock into the open lease, when unlocked; locked, the next unlock seals them.</summary>
    async Task SealIntoLeaseAsync(IReadOnlyList<string> slugs)
    {
        if (Keys.Hello is not { } hello)
            return;
        try
        {
            if (await LeaseControl.SealIntoOpenLeaseAsync(hello, slugs) is { Length: > 0 } message)
                Say(message);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or InvalidDataException or System.Text.Json.JsonException
            or InvalidOperationException or System.Security.Cryptography.CryptographicException)
        {
            Say($"Couldn't add {string.Join(", ", slugs)} to the lease ({e.Message}). Lock and unlock to use them.");
        }
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
        decoys.Dispose();
        Keys.Dispose();
        UserSecrets.Dispose();
        keeper.Dispose();
        activity.Dispose();
        stop.Dispose();
    }
}
