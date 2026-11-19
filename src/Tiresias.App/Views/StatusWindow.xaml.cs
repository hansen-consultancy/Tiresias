using System.Globalization;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App.Views;

/// <summary>
/// The status page: the lock state and every <c>tir doctor</c> check, run on this machine. It follows
/// the agent: a lock or unlock from anywhere (tray, <c>tir</c>, a consent dialog, Win+L) re-runs it.
/// </summary>
public partial class StatusWindow : Window
{
    readonly StatusViewModel model = new();

    public StatusWindow()
    {
        InitializeComponent();
        DataContext = model;
        Loaded += (_, _) => model.Refresh();
        App.Current.Host.StateChanged += OnAgentStateChanged;
        App.Current.Guard.Changed += OnGuardChanged;
        Closed += (_, _) =>
        {
            App.Current.Host.StateChanged -= OnAgentStateChanged;
            App.Current.Guard.Changed -= OnGuardChanged;
        };
    }

    void OnGuardChanged() => Dispatcher.BeginInvoke(model.ShowGuard);

    void OnUnblock(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is BlockedRow row)
        {
            AppLog.Info($"unblocked {row.Path}");
            App.Current.Guard.Unblock(row.Path);
        }
    }

    void OnAgentStateChanged() => Dispatcher.BeginInvoke(model.Refresh);

    void OnClose(object sender, RoutedEventArgs e) => Close();

    void OnSecrets(object sender, RoutedEventArgs e) => App.Current.ShowWindow<SecretsWindow>();

    void OnServices(object sender, RoutedEventArgs e) => App.Current.ShowWindow<ServicesWindow>();

    void OnEnvironment(object sender, RoutedEventArgs e) => ShowEnvironment();

    /// <summary>The environment variables window; its changes can clear the exposed-variables check, so closing it re-runs the checks.</summary>
    EnvironmentWindow ShowEnvironment()
    {
        var window = App.Current.ShowWindow<EnvironmentWindow>();
        window.Closed -= OnRecoveryClosed;
        window.Closed += OnRecoveryClosed;
        return window;
    }

    void OnAbout(object sender, RoutedEventArgs e) => App.Current.ShowWindow<AboutWindow>();

    void OnRestore(object sender, RoutedEventArgs e)
    {
        var window = App.Current.ShowWindow<RecoveryWindow>();
        window.Closed -= OnRecoveryClosed;
        window.Closed += OnRecoveryClosed;
    }

    void OnRecoveryClosed(object? sender, EventArgs e) => model.Refresh();

    /// <summary>Opens the window that fixes the row's finding, filled in from it.</summary>
    void OnReview(object sender, RoutedEventArgs e)
    {
        var fix = ((FrameworkElement)sender).DataContext switch
        {
            CheckRow row => row.Fix,
            FindingRow row => row.Check.Fix,
            _ => null,
        };
        switch (fix)
        {
            case ReviewUserSecrets { UserSecretsId: var id }:
                App.Current.ShowWindow<SecretsWindow>().Select(id);
                break;
            case ProtectVariables:
                ShowEnvironment();
                break;
            case SetUpSqlServer { Server: var server, Database: var database }:
                new SqlServerWindow(server, database) { Owner = this }.ShowDialog();
                model.Refresh();
                break;
            case SetUpRaven { CertificatePath: var path }:
                SetUpRaven(path);
                break;
            case ReferenceConfigurationPackage package:
                model.CopyFix(package.Instruction);
                break;
            case UsePlaceholder { Variable: var variable, Service: var service }:
                ShowEnvironment().PickForPlaceholder(variable, service);
                break;
        }
    }

    /// <summary>Set up a RavenDB with the file found; once it is sealed, offer to move the file to the Recycle Bin.</summary>
    void SetUpRaven(string path)
    {
        var window = RavenServerWindow.ForFile(path);
        window.Owner = this;
        var saved = false;
        window.Saved += _ => saved = true;
        window.ShowDialog();
        if (saved && File.Exists(path)
            && AskWindow.Show(this, Text.Get("Finding_RecycleHeading"), Text.Format("Finding_RecycleBody", path),
                Text.Get("Finding_Recycle"), cancel: Text.Get("Finding_Keep"), safeFirst: true) == true
            && !Desktop.Recycle(path))
            AskWindow.Show(this, null, Text.Format("Finding_RecycleFailed", path), Text.Get("Common_OK"));
        model.Refresh();
    }

    void OnDismiss(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow row)
            row.IsDismissing = true;
    }

    void OnCancelDismiss(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow row)
        {
            row.IsDismissing = false;
            row.Reason = "";
        }
    }

    void OnConfirmDismiss(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow { CanDismiss: true } row)
            model.Dismiss(row.Checks, row.Reason);
    }

    void OnRestoreFinding(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is DismissedRow row)
            model.RestoreFindings(row.Keys);
    }
}

/// <summary>
/// A finding, or findings of one kind shown as one line with their count: where the delivery sits,
/// where its fix takes it, the fix (for one), its members (for a group), and Dismiss with a reason.
/// </summary>
public sealed partial class FindingRow(IReadOnlyList<DoctorCheck> checks) : ObservableObject
{
    public FindingRow(DoctorCheck check)
        : this([check])
    {
    }

    public IReadOnlyList<DoctorCheck> Checks { get; } = checks;

    /// <summary>The finding when there is one; for a group, the first, which speaks for the kind.</summary>
    public DoctorCheck Check => Checks[0];

    public bool IsGroup => Checks.Count > 1;

    /// <summary>A group's findings, each with its own fix and Dismiss; built when first shown.</summary>
    public IReadOnlyList<FindingRow> Members => members ??= IsGroup ? [.. Checks.Select(c => new FindingRow(c))] : [];

    IReadOnlyList<FindingRow>? members;

    public Visibility MembersVisibility => IsGroup ? Visibility.Visible : Visibility.Collapsed;

    public string MembersHeader => Text.Format("Finding_ShowMembers", Checks.Count);

    public string Name { get; } = FindingView.Title(checks);

    public string Detail { get; } = FindingView.Detail(checks);

    public Visibility DetailVisibility => Detail.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string Moves { get; } = FindingView.Moves(checks[0]);

    public string Glyph => Check.Status == DoctorStatus.Fail ? "\uEA39" : "\uE7BA";

    public Brush? Brush => Application.Current.TryFindResource(Check.Status == DoctorStatus.Fail ? "SystemFillColorCriticalBrush" : "SystemFillColorCautionBrush") as Brush;

    public string FixLabel { get; } = checks.Count == 1 && FindingView.Button(checks[0].Fix) is { } button ? Text.Get(button.Label) : "";

    public Visibility FixVisibility => FixLabel.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string FixName => Text.Format("Finding_FixName", FixLabel, Name);

    public string DismissLabel => Text.Get(IsGroup ? "Finding_DismissAll" : "Finding_Dismiss");

    public string DismissName => Text.Format("Finding_DismissName", Name);

    public string Spoken => $"{Name}. {Detail} {Moves}";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DismissingVisibility), nameof(ActionsVisibility))]
    public partial bool IsDismissing { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDismiss))]
    public partial string Reason { get; set; } = "";

    public bool CanDismiss => !string.IsNullOrWhiteSpace(Reason);

    public Visibility DismissingVisibility => IsDismissing ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ActionsVisibility => IsDismissing ? Visibility.Collapsed : Visibility.Visible;
}

/// <summary>Findings set aside together, with the reason given and Show again.</summary>
public sealed record DismissedRow(IReadOnlyList<string> Keys, string Name, string Reason)
{
    public string RestoreName => Text.Format("Finding_RestoreName", Name);
}

/// <summary>One check as a row. Status is said in words and a glyph, never by colour alone.</summary>
/// <param name="Fix">The check's fix; Review opens its window, for the fixes this window has one for.</param>
public sealed record CheckRow(string Name, string StatusText, string Glyph, Brush? Brush, string Detail, DoctorFix? Fix = null)
{
    public string Spoken => $"{Name}: {StatusText}. {Detail}";

    public Visibility ReviewVisibility => ReviewName.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string ReviewName => Fix switch
    {
        ReviewUserSecrets { UserSecretsId: var id } => Text.Format("Status_ReviewName", id),
        ProtectVariables => Text.Get("Status_ReviewEnvironment"),
        _ => "",
    };
}

/// <summary>A program refused without asking since "This wasn't me".</summary>
public sealed record BlockedRow(string Path, string Since)
{
    public string UnblockName => Text.Format("Status_UnblockName", Path);
}

public sealed partial class StatusViewModel : ObservableObject
{
    public ObservableCollection<BlockedRow> Blocked { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(GuardVisibility))]
    public partial Visibility LockedDownVisibility { get; set; } = Visibility.Collapsed;

    public Visibility GuardVisibility => LockedDownVisibility == Visibility.Visible || Blocked.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>The lockdown and the blocklist as they are now.</summary>
    public void ShowGuard()
    {
        var list = App.Current.Guard.Current;
        Blocked.Clear();
        foreach (var program in list.Programs.OrderByDescending(p => p.Since))
            Blocked.Add(new(program.Path, Text.Format("Status_BlockedSince", program.Since.ToLocalTime())));
        LockedDownVisibility = list.LockedDown ? Visibility.Visible : Visibility.Collapsed;
        OnPropertyChanged(nameof(GuardVisibility));
    }

    [ObservableProperty]
    public partial string Headline { get; set; } = "";

    [ObservableProperty]
    public partial string Mode { get; set; } = "";

    [ObservableProperty]
    public partial bool IsRunning { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RestoreVisibility))]
    public partial string RestoreText { get; set; } = "";

    public Visibility RestoreVisibility => RestoreText.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string Build { get; } = Text.Format("Status_Build", Text.Of(AppBuild.Current.Label), AppBuild.Current.Folder);

    [ObservableProperty]
    public partial string LockLabel { get; set; } = "";

    /// <summary>A development build never registers itself: its folder goes stale with the next build.</summary>
    public bool CanStartWithWindows { get; } = AppBuild.Current.Installed;

    [ObservableProperty]
    public partial bool StartsWithWindows { get; set; } = StartWithWindows.IsOn;

    [ObservableProperty]
    public partial string StartWithWindowsNote { get; set; } = Text.Get(AppBuild.Current.Installed ? "Status_StartWithWindowsNote" : "Status_StartWithWindowsDev");

    partial void OnStartsWithWindowsChanged(bool value)
    {
        if (!StartWithWindows.Set(value))
            StartWithWindowsNote = Text.Get("Status_StartWithWindowsFailed");
    }

    /// <summary>Lock right here, or unlock with one Hello prompt; the agent's state change refreshes the page.</summary>
    [RelayCommand]
    async Task ToggleLockAsync()
    {
        if (App.Current.Host.Keys.IsUnlocked)
            await App.Current.LockAsync();
        else
            await App.Current.UnlockAsync(interactive: true);
    }

    public ObservableCollection<CheckRow> Checks { get; } = [];

    public ObservableCollection<FindingRow> Findings { get; } = [];

    public ObservableCollection<DismissedRow> Dismissed { get; } = [];

    public Visibility FindingsVisibility => Findings.Count == 0 ? Visibility.Collapsed : Visibility.Visible;

    public Visibility DismissedVisibility => Dismissed.Count == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string DismissedHeader => Text.Format("Finding_DismissedHeader", Dismissed.Count);

    /// <summary>A line under the findings: what was copied, or why a dismissal couldn't be kept.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FindingMessageVisibility))]
    public partial string FindingMessage { get; set; } = "";

    public Visibility FindingMessageVisibility => FindingMessage.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>The last run's lines, so a dismissal re-sorts them without probing the machine again.</summary>
    IReadOnlyList<DoctorCheck> last = [];

    bool rerun;

    /// <summary>The state line now, then the checks; a change during a run queues one more run rather than overlapping it.</summary>
    public void Refresh()
    {
        ShowState();
        if (IsRunning)
            rerun = true;
        else
            _ = RunAsync();
    }

    void ShowState()
    {
        ShowGuard();
        var view = TrayStatus.Describe(App.Current.Snapshot());
        Headline = Text.Of(view.Headline);
        Mode = view.Mode is null ? Text.Get("Status_ModeNone") : Text.Get("Status_ModeSolo");
        LockLabel = Text.Get(App.Current.Host.Keys.IsUnlocked ? "Tray_Lock" : "Tray_Unlock");
    }

    [RelayCommand]
    async Task RunAsync()
    {
        IsRunning = true;
        last = [];
        Show();
        ShowState();
        try
        {
            // The project folders the secrets editor scans are where appsettings and certificates live.
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var probe = new MachineProbe(ProjectIndexStore.Load().Folders) { Hello = App.Current.Host.Keys.Hello };
            last = await Task.Run(() => Doctor.RunAsync(probe));
            var checks = clock.Elapsed;
            Show();
            // Measured until the page has been laid out and drawn, which is what the wait looks like.
            await Application.Current.Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
            var walk = probe.Scan is { } scan ? $", {scan.Elapsed.TotalSeconds:0.0}s walking {scan.Folders} folders for {scan.Files} files" : "";
            AppLog.Info($"status checks took {checks.TotalSeconds:0.0}s{walk}; showing {last.Count} lines took {(clock.Elapsed - checks).TotalSeconds:0.0}s more");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
        {
            AppLog.Error(e, "status checks");
            Checks.Add(new(Text.Get("Status_CheckFailed"), Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), e.Message));
        }
        finally
        {
            IsRunning = false;
        }
        await ShowRestoreAsync();
        if (rerun)
        {
            rerun = false;
            await RunAsync();
        }
    }

    /// <summary>Sorts the last run's lines into findings, dismissed findings and the other checks.</summary>
    void Show()
    {
        var split = FindingView.Of(last, DismissalStore.Load());
        Findings.Clear();
        foreach (var group in split.Open)
            Findings.Add(new(group));
        Dismissed.Clear();
        foreach (var group in split.Dismissed)
            Dismissed.Add(new(group.Keys, group.Title, group.Reason));
        Checks.Clear();
        foreach (var check in split.Others)
            Checks.Add(Row(check));
        OnPropertyChanged(nameof(FindingsVisibility));
        OnPropertyChanged(nameof(DismissedVisibility));
        OnPropertyChanged(nameof(DismissedHeader));
    }

    public void Dismiss(IEnumerable<DoctorCheck> checks, string reason) =>
        ChangeDismissals(d => checks.Aggregate(d, (all, check) => all.Dismiss(check, reason, DateTimeOffset.Now)));

    public void RestoreFindings(IEnumerable<string> keys) => ChangeDismissals(d => keys.Aggregate(d, (all, key) => all.Restore(key)));

    void ChangeDismissals(Func<Dismissals, Dismissals> change)
    {
        try
        {
            DismissalStore.Update(change);
            FindingMessage = "";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "saving dismissals");
            FindingMessage = Text.Format("Finding_DismissFailed", e.Message);
        }
        Show();
    }

    /// <summary>A fix outside the app: its command goes to the clipboard, and the page says so.</summary>
    public void CopyFix(string command)
    {
        try
        {
            Clipboard.SetText(command);
            FindingMessage = Text.Format("Finding_Copied", command);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            FindingMessage = Text.Format("Finding_CopyFailed", command);
        }
    }

    /// <summary>Whether anything sealed here needs the recovery key; known only while unlocked, since it takes this PC's Hello key.</summary>
    async Task ShowRestoreAsync()
    {
        var hello = App.Current.Host.Keys.Hello;
        try
        {
            var unopened = hello is null ? [] : await Task.Run(() => RecoveryRestore.Unopened(hello));
            RestoreText = unopened.Count == 0 ? "" : Text.Format("Status_RestoreBody", unopened.Count);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException
            or ObjectDisposedException or System.Security.Cryptography.CryptographicException)
        {
            // Locked meanwhile, or a damaged file the checks above already report.
            AppLog.Error(e, "status: sealed secrets this PC can't open");
            RestoreText = "";
        }
    }

    [RelayCommand]
    void Copy()
    {
        var sb = new StringBuilder().AppendLine(Headline).AppendLine(Mode).AppendLine(Build);
        foreach (var check in Findings.SelectMany(row => row.Checks))
            sb.AppendLine(CultureInfo.CurrentCulture, $"{check.Status}  {check.Name}: {check.Detail} [{FindingView.Moves(check)}]");
        foreach (var row in Checks)
            sb.AppendLine(CultureInfo.CurrentCulture, $"{row.StatusText}  {row.Name}: {row.Detail}");
        try
        {
            Clipboard.SetText(sb.ToString());
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // The clipboard is busy; pressing again works.
        }
    }

    [RelayCommand]
    void OpenFolder() => Desktop.OpenDataFolder();

    static CheckRow Row(DoctorCheck check) => check.Status switch
    {
        DoctorStatus.Ok => new(check.Name, Text.Get("Status_Ok"), "\uE73E", Brush("SystemFillColorSuccessBrush"), check.Detail, check.Fix),
        DoctorStatus.Warn => new(check.Name, Text.Get("Status_Warn"), "\uE7BA", Brush("SystemFillColorCautionBrush"), check.Detail, check.Fix),
        _ => new(check.Name, Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), check.Detail, check.Fix),
    };

    static Brush? Brush(string key) => Application.Current.TryFindResource(key) as Brush;
}
