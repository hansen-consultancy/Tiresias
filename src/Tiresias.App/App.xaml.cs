using System.Net.Http;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Tiresias.Decoys;
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
    ProgramGuard? guard;
    readonly ShellConsent shells = new();
    readonly ShellPlaceholders shellPlaceholders = new(TimeProvider.System);
    AgentHost? host;
    TrayController? tray;
    AppUpdates? updates;
    AppAlerts? alerts;
    /// <summary>Whether the Windows session is locked or disconnected, as the last session switch said; assumed not at start.</summary>
    volatile bool sessionLocked;
    readonly Dictionary<Type, Window> windows = [];
    /// <summary>tir, a terminal, NuGet and the tray asking at once share one Windows Hello prompt.</summary>
    readonly SingleFlight<UnlockResult?> unlocking = new();

    internal AgentHost Host => host!;

    /// <summary>Out-of-band alerts (docs/alerts.md): opened at unlock, kept while locked.</summary>
    internal AppAlerts Alerts => alerts!;

    internal ConsentPresenter Consent => consent!;

    /// <summary>The "This wasn't me" lockdown and blocklist.</summary>
    internal ProgramGuard Guard => guard!;

    /// <summary>A window that must not be interrupted (consent, secrets editor, services, first run, recovery) is open.</summary>
    internal bool Busy => consent?.Busy == true || (windows.TryGetValue(typeof(StatusWindow), out var status) && ((StatusWindow)status).Editing)
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

        string? demo = null;
#if DEBUG
        demo = Demo.Requested(e.Args);
#endif
        // Demo mode runs beside the real app, one demo at a time.
        instance = new Mutex(initiallyOwned: true, demo is null ? $@"Local\Tiresias.App.{Environment.UserName}" : $@"Local\Tiresias.Demo.{Environment.UserName}", out var first);
        if (!first && (demo is not null || !await TakeOverAsync()))
        {
            if (demo is not null)
                AskWindow.Tell(null, null, Text.Get("Startup_AlreadyRunning"));
            Shutdown();
            return;
        }
        var unlockAtStart = false;
#if DEBUG
        if (demo is not null)
            unlockAtStart = Demo.Start(demo);
#endif

        consent = new ConsentPresenter(Dispatcher);
        // Before the agent starts: the solo broker audits a trust chain it rejects at startup.
        alerts = new AppAlerts();
        var alertCenter = alerts.Center;
        guard = new ProgramGuard();
        host = new AgentHost(consent, guard.CheckAsync);
        consent.Unlock = async () => (await UnlockAsync(interactive: true)).Ok;
        consent.Gate = guard.Decide;
        consent.SessionLocked = () => sessionLocked;
        consent.Alert = (kind, asker, names) => _ = Task.Run(() => alertCenter.Raise(
            Tiresias.Alerts.AlertSources.Asked(kind, asker.Image, asker.ProcessId, names, ParentsOf(asker.ProcessId), DateTimeOffset.UtcNow)));
        consent.NotMe = (asker, asked, names) =>
        {
            // Before the next waiting request is looked at: from here on everything is refused.
            guard.LockDown();
            _ = Dispatcher.InvokeAsync(() => NotMeAsync(asker, asked, names)).Task.Unwrap();
        };
        host.Log += AppLog.Info;
        // A demo serves nothing: no user-secrets pipe, broker or control pipe for tir, whose names the real app's use.
        if (!DemoMode.On)
        {
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
        }
        // A development build leaves PATH alone: it would put its own tir ahead of the installed one's.
        if (AppBuild.Current.Installed)
            TirOnPath.Ensure();
        AppLog.Info($"started {Text.Of(AppBuild.Current.Label)} from {AppBuild.Current.Folder}");

        tray = new TrayController(this);
        host.StateChanged += () =>
        {
            // The first unlock opens alerts.json; from then on alerts work while locked too.
            if (host.Keys.Hello is { } hello)
                _ = Task.Run(() => alerts.Unlocked(hello));
            // Locked: every terminal asks again, as it would after a restart.
            if (!host.Keys.IsUnlocked)
                ClearEnvironmentConsent();
            Dispatcher.BeginInvoke(Refresh);
        };
        host.DecoyTouched += OnDecoyTouched;
        host.BrokerAudited += (record, at) =>
        {
            if (Tiresias.Alerts.AlertSources.Audited(record, at) is { } alert)
                alertCenter.Raise(alert);
        };
        host.ServiceIncidentsReceived += incidents =>
        {
            foreach (var incident in incidents)
                if (AlertFor(new DecoyTouch(incident.Hit, incident.Parents)) is { } alert)
                    alertCenter.Raise(alert);
            Dispatcher.BeginInvoke(() => tray?.Notify(Text.Get("Notify_Decoy_Title"), Text.Get("Notify_AdminIncidents")));
        };
        host.UserSecrets.FirstSealed += id => Dispatcher.BeginInvoke(() =>
            tray?.Notify(Text.Get("Notify_FirstSealed_Title"), Text.Format("Notify_FirstSealed_Body", id)));
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        Refresh();

        updates = new AppUpdates(this, tray);
        if (!DemoMode.On)
            updates.Start();
        FindingWatch.Start();
        if (unlockAtStart)
            _ = UnlockAsync(interactive: true);

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
            SealedWithoutKey: !recoverySet && AnythingSealed(), AdminTierInstalled: AdminClient.Installed);
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

    internal bool IsOpen<T>() where T : Window => windows.ContainsKey(typeof(T));

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

    /// <summary>Opens Home's window on page <typeparamref name="T"/>; <c>null</c> when the page open there keeps it (unsaved secrets).</summary>
    internal T? ShowPage<T>() where T : System.Windows.Controls.UserControl, new() => ShowWindow<StatusWindow>().Navigate<T>();

    /// <summary>The app's front door: setup while it is unfinished, the status page after.</summary>
    internal void ShowHome()
    {
        if (FirstRunPlan.Needed(SetupFacts()))
            ShowWindow<FirstRunWindow>();
        else
            ShowWindow<StatusWindow>().ShowHome();
    }

    /// <summary>Secrets saved before policy binding are refused by the broker until the user approves binding them.</summary>
    static async Task OfferMigrationAsync()
    {
        try
        {
            if (!await PolicyApproval.MigrateAsync(null))
                AppLog.Info("policy migration declined");
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or InvalidDataException
            or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException)
        {
            AppLog.Info($"policy migration failed: {e.Message}");
        }
    }

    /// <summary>The Windows Hello prompt, then the lease. Interactive: problems get a window with a way forward.</summary>
    /// <returns>Whether the agent ended up unlocked, and what to tell <c>tir</c>.</returns>
    internal async Task<(bool Ok, string Message)> UnlockAsync(bool interactive)
    {
        // After "This wasn't me" only the user, from the app, unlocks: tir, a terminal or NuGet asking can't.
        if (!interactive && guard!.Current.LockedDown)
            return (false, Text.Get("Lockdown_UnlockFromApp"));
        try
        {
            var result = await unlocking.RunAsync(host!.UnlockAsync);
            Refresh();
            if (result is { Ok: false })
            {
                AppLog.Info($"unlocked, lease not opened: {result.Message}");
                if (interactive)
                    ProblemWindow.Show(host.SoloBrokerProblem is not null ? ProblemKind.SoloBrokerDown : ProblemKind.BrokerRefused, result.Message,
                        retry: () => _ = UnlockAsync(true), openStatus: () => ShowWindow<StatusWindow>());
                return (true, Text.Format("Unlock_NoLease", result.Message));
            }
            if (interactive)
                await OfferMigrationAsync();
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
        finally
        {
            // Windows Hello passing from the app is what lifts "This wasn't me", even if the lease then failed.
            if (interactive && host!.Keys.IsUnlocked)
                guard!.Unlocked();
        }
    }

    internal async Task LockAsync()
    {
        consent?.DenyAll();
        await host!.LockAsync();
        Refresh();
    }

    /// <summary>
    /// "This wasn't me", after the lockdown is already in place: lock (which forgets every session
    /// consent, terminal and NuGet allowance, revokes the terminals' placeholders and ends the lease),
    /// find the process and what started it, block the program, record it and show what to do next.
    /// </summary>
    async Task NotMeAsync(Asker asker, string asked, IReadOnlyList<string>? names)
    {
        AppLog.Info($"this wasn't me: {asker.Image ?? "unknown program"} asked for {asked}");
        await LockAsync();
        var (process, chain, sha) = await Task.Run(() =>
        {
            var found = asker.ProcessId is { } pid ? (ProcessTree.Ancestry(pid, 0) is [var self] ? self : null)
                : asker.Image is { } path && System.IO.Path.IsPathFullyQualified(path) ? ProcessTree.Newest(path) : null;
            var parents = ParentsOf(found?.ProcessId);
            return (found, parents, asker.Image is { } program ? guard!.Sha256(program) : null);
        });
        guard!.Block(asker.Image, sha);
        var blocked = asker.Image is { } image && guard.Current.Programs.Any(p => string.Equals(p.Path, image, StringComparison.OrdinalIgnoreCase));
        host!.RecordIncident(asked, process is null ? asker.Image : $"{process.Program} ({process.ProcessId})", chain, blocked);
        alerts!.Center.Raise(Tiresias.Alerts.AlertSources.Asked(Tiresias.Alerts.AlertKind.IncidentReported,
            process?.Program ?? asker.Image, process?.ProcessId ?? asker.ProcessId, names, chain, DateTimeOffset.UtcNow));
        IncidentView view = new(asked, asker.Image, process, chain, blocked);
        IncidentWindow.Show(view);
    }

    static Tiresias.Alerts.AlertEvent? AlertFor(DecoyTouch touch) =>
        Tiresias.Alerts.AlertSources.DecoyUsed(touch.Hit, touch.Parents, touch.What)
            ?? Tiresias.Alerts.AlertSources.DecoyRead(touch.Hit, touch.Parents, touch.What, touch.Routine);

    /// <summary>
    /// A decoy credential was used (docs/decoys.md): block the program, say so, and let Home raise
    /// the finding where the user says whether it was them. A decoy file opened blocks nothing: an
    /// open may be harmless, so only a program that isn't a routine opener is notified of, and Home
    /// raises the finding. Runs on the listener's or the tripwire's thread.
    /// </summary>
    void OnDecoyTouched(DecoyTouch touch)
    {
        if (AlertFor(touch) is { } alert)
            alerts?.Center.Raise(alert);
        var program = touch.Hit.Program;
        if (touch.Hit.Use == DecoyUse.Read)
        {
            if (program is not null && touch.Routine is null)
                Dispatcher.BeginInvoke(() => tray?.Notify(Text.Get("Notify_DecoyRead_Title"),
                    Text.Format("Notify_DecoyRead_Body", System.IO.Path.GetFileName(program), System.IO.Path.GetFileName(touch.Hit.Endpoint))));
            return;
        }
        guard!.BlockForDecoy(program, program is null ? null : guard.Sha256(program));
        Dispatcher.BeginInvoke(() =>
            tray?.Notify(Text.Get("Notify_Decoy_Title"), program is null
                ? Text.Format("Notify_Decoy_Unknown", touch.What)
                : Text.Format("Notify_Decoy_Body", System.IO.Path.GetFileName(program), touch.What)));
    }

    /// <summary>The processes that started <paramref name="processId"/>, nearest first, as the incident record names them.</summary>
    static string[] ParentsOf(int? processId) =>
        processId is { } pid ? [.. ProcessTree.Ancestry(pid).Skip(1).Select(p => $"{p.Program} ({p.ProcessId})")] : [];

    /// <summary>A request that came through <c>tir</c>: the program that ran it is the one asking, not <c>tir</c> itself.</summary>
    static Asker TirCaller(PipeClient caller) =>
        caller.ProcessId is { } pid && ProcessTree.ParentOf(pid) is { } parent ? new(parent.Program, parent.ProcessId) : new(caller.Image, caller.ProcessId);

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
        try
        {
            return await DispatchControlAsync(request, caller, ct);
        }
        catch (EnvironmentIntegrityException e)
        {
            ClearEnvironmentConsent();
            var consumer = request.Op == ControlRequest.NuGetCredential ? "nuget" : "environment";
            Host.RecordPolicyRefusal(consumer, request.Op, caller.Image, caller.Image, e.Message);
            return new(false, e.Message);
        }
    }

    void ClearEnvironmentConsent()
    {
        shells.Clear();
        nugetAllowed.Clear();
        _ = PlaceholderMinter.RevokeAsync(shellPlaceholders.Release((_, _) => false));
    }

    async Task<ControlReply> DispatchControlAsync(ControlRequest request, PipeClient caller, CancellationToken ct)
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
                var approved = await consent!.AskPlaceholderAsync(request.Title ?? "tir", request.Lines ?? [], caller.Image, TirCaller(caller), ct);
                return new(true, Approved: approved);
            case ControlRequest.Environment:
                return await EnvironmentForAsync(request, caller, ct);
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
    async Task<ControlReply> EnvironmentForAsync(ControlRequest request, PipeClient client, CancellationToken ct)
    {
        var caller = client.Image;
        if (!host!.Keys.IsUnlocked)
        {
            var (unlocked, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
            if (!unlocked)
                return new(false, message);
        }
        if (host.Keys.Hello is not { } hello)
            return new(false, Text.Get("Environment_Locked"));
        var snapshot = await Task.Run(() => EnvironmentStore.ReadForDelivery(hello), ct);
        var endpoint = PlaceholderMinter.Endpoint;
        var (variables, missing, terms) = snapshot.SelectForCommand(request.Directory, request.Names, endpoint);
        if (missing.Count > 0)
            return new(false, Text.Format("Environment_NotSealed", string.Join(", ", missing)));
        if (variables.Count == 0)
            return new(true, Text.Get("Environment_NoneSealed"), Approved: true, Variables: new Dictionary<string, string>());
        var program = request.Title ?? "tir run";
        var approved = await consent!.AskEnvironmentAsync(program, request.Lines, terms, caller,
            TirCaller(client), ct);
        if (!approved)
        {
            host.RecordEnvironment(false, program, terms, caller);
            return new(true, Approved: false);
        }
        // tir revokes these placeholders when the command exits.
        var delivery = await snapshot.DeliverAsync(variables, endpoint,
            (placeholder, _) => PlaceholderMinter.MintAsync(hello, placeholder, $"run:{program}", caller), PlaceholderMinter.RevokeAsync, ct,
            () => host.Keys.Hello == hello);
        host.RecordEnvironment(true, program, terms, caller);
        return new(true, Note(delivery), Approved: true, Variables: delivery.Variables);
    }

    static string? Note(Delivery delivery) => delivery.Problems.Count > 0 ? string.Join(Environment.NewLine, delivery.Problems) : null;

    /// <summary>
    /// The terminal hook, on opening a terminal and on each change of folder. Asks again for new
    /// variables, folder overrides and changed deliveries, and after a no stays quiet in that terminal
    /// until the user asks again. Nothing sealed means no prompt at all, not even to unlock.
    /// </summary>
    async Task<ControlReply> ShellEnvironmentAsync(ControlRequest request, PipeClient caller, CancellationToken ct)
    {
        if (caller.ProcessId is not { } pid || request.Shell is not { } shellId || request.Directory is not { } directory
            || ProcessTree.ShellOf(pid, shellId) is not { } shell)
            return new(false, Text.Get("Shell_Unrecognised"));
        if (!EnvironmentStore.Exists)
        {
            ClearEnvironmentConsent();
            return new(true, Approved: true, Variables: new Dictionary<string, string>());
        }
        var policy = await Guard.CheckAsync(shell.Program, caller.Image, ct);
        ControlReply Refuse(string why)
        {
            Host.RecordPolicyRefusal("environment", "terminal", shell.Program, caller.Image, why);
            return new(true, why, Approved: false);
        }
        if (policy.Refusal is { } refused)
            return Refuse(refused);

        shells.Prune(ProcessTree.IsRunning);
        if (!host!.Keys.IsUnlocked && shells.HasRefused(shell, policy.Scope) && !request.AskAgain)
            return new(true, Approved: false);
        if (!host.Keys.IsUnlocked)
        {
            var (unlocked, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
            if (!unlocked)
            {
                shells.Refuse(shell, policy.Scope);
                return new(true, Text.Format("Shell_NotUnlocked", message), Approved: false);
            }
        }
        if (host.Keys.Hello is not { } hello)
            return new(false, Text.Get("Environment_Locked"));
        _ = PlaceholderMinter.RevokeAsync(shellPlaceholders.Release(ProcessTree.IsRunning));
        var snapshot = await Task.Run(() => EnvironmentStore.ReadForDelivery(hello), ct);
        var sealedNow = snapshot.Environment;
        var endpoint = PlaceholderMinter.Endpoint;
        var variables = sealedNow.ResolveWithFolders(directory);
        var access = variables.ToDictionary(v => v.Variable.Name, v => EnvironmentVariableAccess.For(sealedNow, v.Variable.Name, v.Folder, endpoint),
            StringComparer.OrdinalIgnoreCase);
        await PlaceholderMinter.RevokeAsync(shellPlaceholders.ReleaseChanged(shell, access));
        var (answer, fresh) = shells.Check(shell, access.Values, request.AskAgain, policy.Scope);
        IReadOnlyList<EnvironmentVariableAccess> approvedNow = [];
        string? note = null;
        if (answer == ShellAnswer.Ask)
        {
            var terms = fresh.Select(item => item.Describe()).ToArray();
            var approved = await consent!.AskShellAsync(shell.Program, shell.ProcessId, directory, terms, ct);
            AppLog.Info($"terminal {System.IO.Path.GetFileName(shell.Program)} ({shell.ProcessId}): {(approved ? "allowed" : "denied")} {fresh.Count} environment variable(s)");
            if (!approved)
                host.RecordEnvironment(false, "terminal", terms, shell.Program);
            snapshot.EnsureCurrent();
            if (host.Keys.Hello != hello)
                return Refuse(Text.Get("Environment_Locked"));
            if (approved)
            {
                shells.Allow(shell, fresh, policy.Scope);
                approvedNow = fresh;
                fresh = [];
            }
            else
            {
                shells.Refuse(shell, policy.Scope);
                note = Text.Get("Shell_Refused");
            }
        }
        var withheld = fresh.Select(a => a.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var given = variables.Select(v => v.Variable).Where(v => !withheld.Contains(v.Name));
        var observed = $"{shell.Program} ({shell.ProcessId})";
        var (delivery, refusal) = await ShellConsent.ReleaseAsync(policy, () => Guard.CheckAsync(shell.Program, caller.Image, ct),
            () => snapshot.DeliverAsync(given, endpoint,
                (placeholder, _) => shellPlaceholders.GetAsync(shell, access[placeholder.Variable],
                    () => PlaceholderMinter.MintAsync(hello, placeholder, $"terminal:{System.IO.Path.GetFileNameWithoutExtension(shell.Program)}", observed)),
                PlaceholderMinter.RevokeAsync, ct));
        if (delivery is null)
        {
            _ = PlaceholderMinter.RevokeAsync(shellPlaceholders.Release((id, started) => id != shell.ProcessId || started != shell.Started));
            return Refuse(refusal!);
        }
        snapshot.EnsureCurrent();
        if (host.Keys.Hello != hello)
        {
            ClearEnvironmentConsent();
            return Refuse(Text.Get("Environment_Locked"));
        }
        if (approvedNow.Count > 0)
            host.RecordEnvironment(true, "terminal", approvedNow.Select(a =>
                delivery.Variables.ContainsKey(a.Name) ? a.Describe() : $"{a.Describe()} (not delivered)"), shell.Program);
        return new(true, string.Join(Environment.NewLine, new[] { note, Note(delivery) }.OfType<string>()) is { Length: > 0 } text ? text : null,
            Approved: true, Variables: delivery.Variables);
    }

    /// <summary>Feed mappings approved for each program until the agent locks.</summary>
    readonly NuGetConsent nugetAllowed = new();

    /// <summary>
    /// The NuGet credential plugin, asked by <c>dotnet restore</c>, Visual Studio or Rider. The
    /// program asking is the plugin's parent, never anything the plugin says. Only a source mapped
    /// to a sealed variable gets an answer; any other is left to NuGet's other providers.
    /// </summary>
    async Task<ControlReply> NuGetCredentialAsync(ControlRequest request, PipeClient caller, CancellationToken ct)
    {
        if (!Uri.TryCreate(request.Title, UriKind.Absolute, out var uri))
            return new(false, Text.Get("NuGet_BadSource"));
        if (!EnvironmentStore.Exists)
        {
            ClearEnvironmentConsent();
            return new(true, Approved: false);
        }
        if (caller.ProcessId is not { } pid || ProcessTree.ParentOf(pid) is not { } program)
            return new(false, Text.Get("Shell_Unrecognised"));
        var policy = await Guard.CheckAsync(program.Program, caller.Image, ct);
        ControlReply Refuse(string why)
        {
            Host.RecordPolicyRefusal("nuget", uri.Host, program.Program, caller.Image, why);
            return new(true, why, Approved: false);
        }
        if (policy.Refusal is { } refused)
            return Refuse(refused);
        if (!host!.Keys.IsUnlocked)
        {
            var (unlocked, message) = await Dispatcher.InvokeAsync(() => UnlockAsync(interactive: false)).Task.Unwrap();
            if (!unlocked)
                return new(false, message);
        }
        if (host.Keys.Hello is not { } hello)
            return new(false, Text.Get("Environment_Locked"));
        var snapshot = await Task.Run(() => EnvironmentStore.ReadForDelivery(hello), ct);
        var environment = snapshot.Environment;
        if (nugetAllowed.Match(environment, uri) is not { } source)
            return new(true, Approved: false);
        if (environment.Global.FirstOrDefault(v => string.Equals(v.Name, source.Variable, StringComparison.OrdinalIgnoreCase)) is not { } variable)
        {
            host.RecordNuGet(NuGetOutcome.NotSealed, program.Program, program.ProcessId, source.Source, source.Variable);
            return new(true, Text.Format("NuGet_VariableMissing", source.Variable, source.Source), Approved: false);
        }
        if (request.AskAgain)
        {
            host.RecordNuGet(NuGetOutcome.RetryRefused, program.Program, program.ProcessId, source.Source, variable.Name);
            return new(true, Text.Format("NuGet_Refused", source.Variable, source.Source), Approved: false);
        }

        var (outcome, why) = await nugetAllowed.DecideAsync(program.Program, source, policy,
            () => consent!.AskNuGetAsync(program.Program, program.ProcessId, source, ct),
            async () =>
            {
                var current = await Guard.CheckAsync(program.Program, caller.Image, ct);
                return host.Keys.Hello == hello ? current : current with { Refusal = Text.Get("Environment_Locked") };
            },
            snapshot.EnsureCurrent);
        if (why is not null)
            return Refuse(why);
        host.RecordNuGet(outcome, program.Program, program.ProcessId, source.Source, variable.Name);
        if (outcome == NuGetOutcome.Denied)
            return new(true, Approved: false);
        return new(true, Approved: true, Username: source.Username, Password: variable.Value);
    }

    void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        sessionLocked = AlertTriggers.SessionLocked(sessionLocked, e.Reason.ToString());
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
        // Unsaved secrets are saved, discarded or keep the app running: Shutdown would close the window without asking.
        if (windows.TryGetValue(typeof(StatusWindow), out var status) && !((StatusWindow)status).CanLeavePage())
            return;
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        updates?.Dispose();
        FindingWatch.Stop();
        tray?.Dispose();
        await stop.CancelAsync();
        if (host is not null)
            await host.DisposeAsync();
        if (alerts is not null)
            await alerts.DisposeAsync();
        consent?.Dispose();
        instance?.ReleaseMutex();
        instance?.Dispose();
#if DEBUG
        Demo.End();
#endif
        Shutdown();
    }
}
