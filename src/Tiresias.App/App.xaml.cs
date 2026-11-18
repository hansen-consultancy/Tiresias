using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Tiresias.EnvironmentVariables;
using Tiresias.UserSecrets;

namespace Tiresias.App;

/// <summary>
/// The tray app: one per user session. It is the agent (<see cref="AgentHost"/>: unlocked keys,
/// user-secrets pipe, lease keeper, solo broker), shows every consent question, and answers
/// <c>tir</c> on the control pipe. A second start of the same copy brings the first forward and
/// exits; a different copy (a development build, the installed app) offers to take over.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "WPF never disposes the Application; Quit disposes these in order (the lease ends before the pipes close).")]
public partial class App : Application
{
    readonly CancellationTokenSource stop = new();
    Mutex? instance;
    ConsentPresenter? consent;
    readonly ShellConsent shells = new();
    readonly ShellPlaceholders shellPlaceholders = new(TimeProvider.System);
    AgentHost? host;
    TrayController? tray;
    AppUpdates? updates;
    readonly Dictionary<Type, Window> windows = [];

    internal AgentHost Host => host!;

    internal ConsentPresenter Consent => consent!;

    /// <summary>A window that must not be interrupted (consent, secrets editor, services, first run, recovery) is open.</summary>
    internal bool Busy => consent?.Busy == true || windows.ContainsKey(typeof(SecretsWindow)) || windows.ContainsKey(typeof(ServicesWindow))
        || windows.ContainsKey(typeof(FirstRunWindow)) || windows.ContainsKey(typeof(RecoveryWindow));

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
        if (!first && !await TakeOverAsync())
        {
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
        // A development build leaves PATH alone: it would put its own tir ahead of the installed one's.
        if (AppBuild.Current.Installed)
            TirOnPath.Ensure();
        AppLog.Info($"started {Text.Of(AppBuild.Current.Label)} from {AppBuild.Current.Folder}");

        tray = new TrayController(this);
        host.StateChanged += () =>
        {
            // Locked: every terminal asks again, as it would after a restart.
            if (!host.Keys.IsUnlocked)
            {
                shells.Clear();
                _ = PlaceholderMinter.RevokeAsync(shellPlaceholders.Release((_, _) => false));
                lock (nugetAllowed)
                    nugetAllowed.Clear();
            }
            Dispatcher.BeginInvoke(Refresh);
        };
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

    /// <summary>
    /// Another copy holds the session. The same copy is brought forward; a different one (say the
    /// installed app while this is a development build) is asked to quit, after the user agrees.
    /// </summary>
    /// <returns>Whether this copy now owns the session.</returns>
    async Task<bool> TakeOverAsync()
    {
        var running = await TryControlAsync(new(ControlRequest.Ping));
        if (running is null)
        {
            AskWindow.Tell(null, null, Text.Get("Startup_AlreadyRunning"));
            return false;
        }
        if (running.Folder is null)
        {
            AskWindow.Tell(null, Text.Get("Startup_SwitchHeading"), Text.Get("Startup_SwitchOld"));
            return false;
        }
        if (AppBuild.Current.SameCopyAs(running.Folder))
        {
            await TryControlAsync(new(ControlRequest.Show));
            return false;
        }
        var body = Text.Format("Startup_SwitchBody", running.Build, running.Folder, Text.Of(AppBuild.Current.Label), AppBuild.Current.Folder);
        if (AskWindow.Show(null, Text.Get("Startup_SwitchHeading"), body, Text.Get("Startup_Switch"), cancel: Text.Get("Common_Cancel")) != true)
            return false;
        var reply = await TryControlAsync(new(ControlRequest.Quit));
        if (reply is not { Ok: true })
        {
            AskWindow.Tell(null, Text.Get("Startup_SwitchHeading"), reply?.Message ?? Text.Get("Startup_SwitchFailed"));
            return false;
        }
        // The other copy releases the mutex last, after its agent pipes are closed.
        for (var waited = TimeSpan.Zero; waited < TimeSpan.FromSeconds(15); waited += TimeSpan.FromMilliseconds(200))
        {
            if (OwnsInstance())
            {
                AppLog.Info($"took over from {running.Build} in {running.Folder}");
                return true;
            }
            await Task.Delay(200);
        }
        AskWindow.Tell(null, Text.Get("Startup_SwitchHeading"), Text.Get("Startup_SwitchFailed"));
        return false;
    }

    bool OwnsInstance()
    {
        try
        {
            return instance!.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            // The other copy ended without releasing it; it is ours now all the same.
            return true;
        }
    }

    static async Task<ControlReply?> TryControlAsync(ControlRequest request)
    {
        try
        {
            return await ControlClient.TryAsync(request, TimeSpan.FromSeconds(10));
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
            return null;
        }
    }

    internal static SetupFacts SetupFacts()
    {
        var recoverySet = KeyringStore.Settings.RecoveryPublicKey is not null;
        return new(HelloKeyWrapper.Exists(), recoverySet, KeyringStore.Broker is not null, AppSettings.Load().SetupSkipped,
            SealedWithoutKey: !recoverySet && AnythingSealed());
    }

    /// <summary>A damaged vault or secrets file must not stop the app starting: the status page reports it.</summary>
    static bool AnythingSealed()
    {
        try
        {
            return RecoveryRestore.AnythingSealed();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
        {
            AppLog.Error(e, "looking for sealed secrets");
            return false;
        }
    }

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
        var server = new AgentPipeServer<ControlRequest, ControlReply, PipeClient>(ControlClient.PipeName, HandleControlAsync, PipeCaller.Client);
        server.ConnectionFailed += e => AppLog.Error(e, "control pipe");
        var serving = server.RunAsync(stop.Token);
        serving.ContinueWith(t => AppLog.Error(t.Exception!, "control pipe stopped"), TaskContinuationOptions.OnlyOnFaulted);
    }

    /// <summary><c>tir</c>'s requests. Runs off the UI thread; anything visual is marshalled.</summary>
    async Task<ControlReply> HandleControlAsync(ControlRequest request, PipeClient caller, CancellationToken ct)
    {
        if (request.V > ControlRequest.Version)
            return new(false, Text.Get("Control_NewerTir"));
        switch (request.Op)
        {
            case ControlRequest.Ping:
                return new(true, State: await Dispatcher.InvokeAsync(() => Text.Of(TrayStatus.Describe(Snapshot()).Headline)),
                    Build: Text.Of(AppBuild.Current.Label), Folder: AppBuild.Current.Folder);
            case ControlRequest.Quit:
                if (await Dispatcher.InvokeAsync(() => Busy))
                    return new(false, Text.Get("Startup_SwitchBusy"));
                AppLog.Info("quitting: another copy is taking over");
                // After the reply is on its way: quitting closes this pipe.
                _ = Task.Delay(250, CancellationToken.None).ContinueWith(_ => Dispatcher.BeginInvoke(Quit), TaskScheduler.Default);
                return new(true);
            case ControlRequest.Show:
                await Dispatcher.InvokeAsync(ShowHome);
                return new(true);
            case ControlRequest.Consent:
                var approved = await consent!.AskPlaceholderAsync(request.Title ?? "tir", request.Lines ?? [], caller.Image, ct);
                return new(true, Approved: approved);
            case ControlRequest.Environment:
                return await EnvironmentForAsync(request, caller.Image, ct);
            case ControlRequest.ShellEnvironment:
                return await ShellEnvironmentAsync(request, caller, ct);
            case ControlRequest.NuGetCredential:
                return await NuGetCredentialAsync(request, caller, ct);
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

    /// <summary><c>tir run</c>: unlocks if needed, then hands the sealed variables over only if the user allows this program.</summary>
    async Task<ControlReply> EnvironmentForAsync(ControlRequest request, string? caller, CancellationToken ct)
    {
        if (!host!.Keys.IsUnlocked)
        {
            var (unlocked, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
            if (!unlocked)
                return new(false, message);
        }
        if (host.Keys.Hello is not { } hello)
            return new(false, Text.Get("Environment_Locked"));
        var sealedNow = await Task.Run(() => EnvironmentStore.Open(hello).Environment, ct);
        var (variables, missing) = SealedVariables.Pick(request.Directory is { } directory ? sealedNow.Resolve(directory) : sealedNow.Global, request.Names);
        if (missing.Count > 0)
            return new(false, Text.Format("Environment_NotSealed", string.Join(", ", missing)));
        if (variables.Count == 0)
            return new(true, Text.Get("Environment_NoneSealed"), Approved: true, Variables: new Dictionary<string, string>());
        var program = request.Title ?? "tir run";
        var approved = await consent!.AskEnvironmentAsync(program, [.. variables.Select(v => EnvironmentDelivery.Describe(sealedNow, v.Name))], caller, ct);
        AppLog.Info($"tir run {program}: {(approved ? "allowed" : "denied")} {variables.Count} environment variable(s)");
        host.RecordEnvironment(approved, program, variables.Select(v => EnvironmentDelivery.Describe(sealedNow, v.Name)), caller);
        if (!approved)
            return new(true, Approved: false);
        // tir revokes these placeholders when the command exits.
        var delivery = await EnvironmentDelivery.DeliverAsync(sealedNow, variables, PlaceholderMinter.Endpoint,
            (placeholder, _) => PlaceholderMinter.MintAsync(placeholder, $"run:{program}", caller), ct);
        return new(true, Note(delivery), Approved: true, Variables: delivery.Variables);
    }

    static string? Note(Delivery delivery) => delivery.Problems.Count > 0 ? string.Join(Environment.NewLine, delivery.Problems) : null;

    /// <summary>
    /// The terminal hook, on opening a terminal and on each change of folder. Asks once per shell
    /// session (again only for names a folder adds), and after a no stays quiet in that terminal
    /// until the user asks again. Nothing sealed means no prompt at all, not even to unlock.
    /// </summary>
    async Task<ControlReply> ShellEnvironmentAsync(ControlRequest request, PipeClient caller, CancellationToken ct)
    {
        if (caller.ProcessId is not { } pid || request.Shell is not { } shellId || request.Directory is not { } directory
            || ProcessTree.ShellOf(pid, shellId) is not { } shell)
            return new(false, Text.Get("Shell_Unrecognised"));
        if (!EnvironmentStore.IsSealed)
            return new(true, Approved: true, Variables: new Dictionary<string, string>());
        shells.Prune(ProcessTree.IsRunning);
        if (!host!.Keys.IsUnlocked && shells.HasRefused(shell) && !request.AskAgain)
            return new(true, Approved: false);
        if (!host.Keys.IsUnlocked)
        {
            var (unlocked, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
            if (!unlocked)
            {
                shells.Refuse(shell);
                return new(true, Text.Format("Shell_NotUnlocked", message), Approved: false);
            }
        }
        if (host.Keys.Hello is not { } hello)
            return new(false, Text.Get("Environment_Locked"));
        _ = PlaceholderMinter.RevokeAsync(shellPlaceholders.Release(ProcessTree.IsRunning));
        var sealedNow = await Task.Run(() => EnvironmentStore.Open(hello).Environment, ct);
        var variables = sealedNow.Resolve(directory);
        var (answer, fresh) = shells.Check(shell, variables.Select(v => v.Name), request.AskAgain);
        string? note = null;
        if (answer == ShellAnswer.Ask)
        {
            var approved = await consent!.AskShellAsync(shell.Program, directory, [.. fresh.Select(name => EnvironmentDelivery.Describe(sealedNow, name))], ct);
            AppLog.Info($"terminal {System.IO.Path.GetFileName(shell.Program)} ({shell.ProcessId}): {(approved ? "allowed" : "denied")} {fresh.Count} environment variable(s)");
            if (approved)
            {
                shells.Allow(shell, fresh);
                fresh = [];
            }
            else
            {
                shells.Refuse(shell);
                note = Text.Get("Shell_Refused");
            }
        }
        // Whatever the shell was allowed before still reaches it; only the names it was refused stay out.
        var given = variables.Where(v => !fresh.Contains(v.Name, StringComparer.OrdinalIgnoreCase));
        var observed = $"{shell.Program} ({shell.ProcessId})";
        var delivery = await EnvironmentDelivery.DeliverAsync(sealedNow, given, PlaceholderMinter.Endpoint,
            (placeholder, _) => shellPlaceholders.GetAsync(shell, placeholder,
                () => PlaceholderMinter.MintAsync(placeholder, $"terminal:{System.IO.Path.GetFileNameWithoutExtension(shell.Program)}", observed)), ct);
        return new(true, string.Join(Environment.NewLine, new[] { note, Note(delivery) }.OfType<string>()) is { Length: > 0 } text ? text : null,
            Approved: true, Variables: delivery.Variables);
    }

    /// <summary>Programs allowed a NuGet source's token until the agent locks: image path and variable.</summary>
    readonly HashSet<(string Program, string Variable)> nugetAllowed = [];

    /// <summary>
    /// The NuGet credential plugin, asked by <c>dotnet restore</c>, Visual Studio or Rider. The
    /// program asking is the plugin's parent, never anything the plugin says. Only a source mapped
    /// to a sealed variable gets an answer; any other is left to NuGet's other providers.
    /// </summary>
    async Task<ControlReply> NuGetCredentialAsync(ControlRequest request, PipeClient caller, CancellationToken ct)
    {
        if (!Uri.TryCreate(request.Title, UriKind.Absolute, out var uri))
            return new(false, Text.Get("NuGet_BadSource"));
        if (!EnvironmentStore.IsSealed)
            return new(true, Approved: false);
        if (caller.ProcessId is not { } pid || ProcessTree.ParentOf(pid) is not { } program)
            return new(false, Text.Get("Shell_Unrecognised"));
        if (!host!.Keys.IsUnlocked)
        {
            var (unlocked, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
            if (!unlocked)
                return new(false, message);
        }
        if (host.Keys.Hello is not { } hello)
            return new(false, Text.Get("Environment_Locked"));
        var environment = await Task.Run(() => EnvironmentStore.Open(hello).Environment, ct);
        if (environment.NuGetSourceFor(uri) is not { } source)
            return new(true, Approved: false);
        if (environment.Global.FirstOrDefault(v => string.Equals(v.Name, source.Variable, StringComparison.OrdinalIgnoreCase)) is not { } variable)
            return new(true, Text.Format("NuGet_VariableMissing", source.Variable, source.Source), Approved: false);
        if (request.AskAgain)
            return new(true, Text.Format("NuGet_Refused", source.Variable, source.Source), Approved: false);

        var key = (program.Program, variable.Name);
        bool known;
        lock (nugetAllowed)
            known = nugetAllowed.Contains(key);
        if (!known)
        {
            var answer = await consent!.AskNuGetAsync(program.Program, source.Source, variable.Name, ct);
            AppLog.Info($"nuget {System.IO.Path.GetFileName(program.Program)} {source.Source}: {answer} {variable.Name}");
            if (answer == ConsentAnswer.Deny)
                return new(true, Approved: false);
            if (answer == ConsentAnswer.AllowForSession)
                lock (nugetAllowed)
                    nugetAllowed.Add(key);
        }
        return new(true, Approved: true, Username: source.Username, Password: variable.Value);
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
