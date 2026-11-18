using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Tiresias.UserSecrets;

namespace Tiresias.App;

/// <summary>
/// The tray app: one per user session. It is the agent (<see cref="AgentHost"/>: unlocked keys,
/// user-secrets pipe, lease keeper, solo broker), shows every consent question, and answers
/// <c>tir</c> on the control pipe. A second start hands over to the first and exits.
/// </summary>
public partial class App : Application
{
    readonly CancellationTokenSource stop = new();
    Mutex? instance;
    ConsentPresenter? consent;
    AgentHost? host;
    TrayController? tray;
    AppUpdates? updates;
    readonly Dictionary<Type, Window> windows = [];

    internal AgentHost Host => host!;

    internal ConsentPresenter Consent => consent!;

    /// <summary>A window that must not be interrupted (consent, secrets editor, services, first run) is open.</summary>
    internal bool Busy => consent?.Busy == true || windows.ContainsKey(typeof(SecretsWindow)) || windows.ContainsKey(typeof(ServicesWindow))
        || windows.ContainsKey(typeof(FirstRunWindow));

    internal static new App Current => (App)Application.Current;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            AppLog.Error(args.Exception, "unobserved task");
            args.SetObserved();
        };

        instance = new Mutex(initiallyOwned: true, $@"Local\Tiresias.App.{Environment.UserName}", out var first);
        if (!first)
        {
            // Already running in this session: bring it forward instead of starting a second agent.
            if (await ControlClient.TryAsync(new(ControlRequest.Show)) is null)
                AskWindow.Tell(null, null, Text.Get("Startup_AlreadyRunning"));
            Shutdown();
            return;
        }

        consent = new ConsentPresenter(Dispatcher);
        host = new AgentHost(consent);
        consent.Unlock = async () => (await UnlockAsync(interactive: true)).Ok;
        host.Log += AppLog.Info;
        try
        {
            await host.StartAsync();
        }
        catch (IOException)
        {
            AskWindow.Tell(null, null, Text.Get("Startup_OtherAgent"));
            Shutdown();
            return;
        }
        StartControlPipe();
        TirOnPath.Ensure();

        tray = new TrayController(this);
        host.StateChanged += () => Dispatcher.BeginInvoke(Refresh);
        host.UserSecrets.FirstSealed += id => Dispatcher.BeginInvoke(() =>
            tray?.Notify(Text.Get("Notify_FirstSealed_Title"), Text.Format("Notify_FirstSealed_Body", id)));
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        Refresh();

        updates = new AppUpdates(this, tray);
        updates.Start();

        if (FirstRunPlan.Needed(SetupFacts()))
            ShowWindow<FirstRunWindow>();
        else if (host.SoloBrokerProblem is not null)
            ProblemWindow.Show(ProblemKind.SoloBrokerDown, host.SoloBrokerProblem, retry: () => _ = UnlockAsync(interactive: true));
    }

    internal static SetupFacts SetupFacts() =>
        new(HelloKeyWrapper.Exists(), KeyringStore.Settings.RecoveryPublicKey is not null, KeyringStore.Broker is not null, AppSettings.Load().SetupSkipped);

    internal AgentSnapshot Snapshot() =>
        new(!FirstRunPlan.Needed(SetupFacts()), host!.Keys.IsUnlocked, KeyringStore.Broker is not null, KeyringStore.Tenant is { Solo: true },
            KeyringStore.Lease?.HardCapAt, host.SoloBrokerProblem);

    internal void Refresh() => tray?.Refresh(Snapshot());

    /// <summary>Opens one window of a kind, or brings the open one forward.</summary>
    internal T ShowWindow<T>() where T : Window, new()
    {
        if (windows.TryGetValue(typeof(T), out var open))
        {
            if (open.WindowState == WindowState.Minimized)
                open.WindowState = WindowState.Normal;
            open.Activate();
            return (T)open;
        }
        var window = new T();
        windows[typeof(T)] = window;
        window.Closed += (_, _) =>
        {
            windows.Remove(typeof(T));
            Refresh();
        };
        window.Show();
        window.Activate();
        return window;
    }

    /// <summary>The app's front door: setup while it is unfinished, the status page after.</summary>
    internal void ShowHome()
    {
        if (FirstRunPlan.Needed(SetupFacts()))
            ShowWindow<FirstRunWindow>();
        else
            ShowWindow<StatusWindow>();
    }

    /// <summary>The Windows Hello prompt, then the lease. Interactive: problems get a window with a way forward.</summary>
    /// <returns>Whether the agent ended up unlocked, and what to tell <c>tir</c>.</returns>
    internal async Task<(bool Ok, string Message)> UnlockAsync(bool interactive)
    {
        try
        {
            var result = await host!.UnlockAsync();
            Refresh();
            if (result is { Ok: false })
            {
                AppLog.Info($"unlocked, lease not opened: {result.Message}");
                if (interactive)
                    ProblemWindow.Show(host.SoloBrokerProblem is not null ? ProblemKind.SoloBrokerDown : ProblemKind.BrokerRefused, result.Message,
                        retry: () => _ = UnlockAsync(true), openStatus: () => ShowWindow<StatusWindow>());
                return (true, Text.Format("Unlock_NoLease", result.Message));
            }
            return (true, result is null ? Text.Get("Unlock_Done") : Text.Format("Unlock_DoneLease", result.Message));
        }
        catch (Exception e) when (e is InvalidOperationException or HttpRequestException or TaskCanceledException or IOException
            or System.Text.Json.JsonException or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            Refresh();
            if (interactive)
                ProblemWindow.Show(e, "unlock", retry: () => _ = UnlockAsync(true), finishSetup: ShowHome);
            else
                AppLog.Error(e, "unlock from tir");
            return (false, e.Message);
        }
    }

    internal async Task LockAsync()
    {
        consent?.DenyAll();
        await host!.LockAsync();
        Refresh();
    }

    void StartControlPipe()
    {
        var server = new AgentPipeServer<ControlRequest, ControlReply>(ControlClient.PipeName, HandleControlAsync, PipeCaller.Identify);
        server.ConnectionFailed += e => AppLog.Error(e, "control pipe");
        var serving = server.RunAsync(stop.Token);
        serving.ContinueWith(t => AppLog.Error(t.Exception!, "control pipe stopped"), TaskContinuationOptions.OnlyOnFaulted);
    }

    /// <summary><c>tir</c>'s requests. Runs off the UI thread; anything visual is marshalled.</summary>
    async Task<ControlReply> HandleControlAsync(ControlRequest request, string? caller, CancellationToken ct)
    {
        if (request.V > ControlRequest.Version)
            return new(false, Text.Get("Control_NewerTir"));
        switch (request.Op)
        {
            case ControlRequest.Ping:
                return new(true, State: await Dispatcher.InvokeAsync(() => Text.Of(TrayStatus.Describe(Snapshot()).Headline)));
            case ControlRequest.Show:
                await Dispatcher.InvokeAsync(ShowHome);
                return new(true);
            case ControlRequest.Consent:
                var approved = await consent!.AskPlaceholderAsync(request.Title ?? "tir", request.Lines ?? [], caller, ct);
                return new(true, Approved: approved);
            case ControlRequest.Unlock:
                var (ok, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
                return new(ok, message);
            case ControlRequest.Lock:
                await Dispatcher.InvokeAsync(LockAsync).Task.Unwrap();
                return new(true, Text.Get("Lock_Done"));
            default:
                return new(false, Text.Format("Control_Unknown", request.Op));
        }
    }

    void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        // The agent locks its keys itself; open consent dialogs are answered Deny here so none waits behind the lock screen.
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff or SessionSwitchReason.ConsoleDisconnect)
            consent?.DenyAll();
        Dispatcher.BeginInvoke(Refresh);
    }

    void OnPowerModeChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend)
            consent?.DenyAll();
        Dispatcher.BeginInvoke(Refresh);
    }

    void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        ProblemWindow.Show(e.Exception, "unhandled");
    }

    internal async void Quit()
    {
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        updates?.Dispose();
        tray?.Dispose();
        await stop.CancelAsync();
        if (host is not null)
            await host.DisposeAsync();
        consent?.Dispose();
        instance?.ReleaseMutex();
        instance?.Dispose();
        Shutdown();
    }
}
