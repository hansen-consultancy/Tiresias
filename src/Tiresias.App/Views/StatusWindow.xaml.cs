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
    void ShowEnvironment()
    {
        var window = App.Current.ShowWindow<EnvironmentWindow>();
        window.Closed -= OnRecoveryClosed;
        window.Closed += OnRecoveryClosed;
    }

    void OnAbout(object sender, RoutedEventArgs e) => App.Current.ShowWindow<AboutWindow>();

    void OnRestore(object sender, RoutedEventArgs e)
    {
        var window = App.Current.ShowWindow<RecoveryWindow>();
        window.Closed -= OnRecoveryClosed;
        window.Closed += OnRecoveryClosed;
    }

    void OnRecoveryClosed(object? sender, EventArgs e) => model.Refresh();

    /// <summary>Opens the secrets editor on the row's project: the fix for a user-secrets line.</summary>
    void OnReview(object sender, RoutedEventArgs e)
    {
        switch (((FrameworkElement)sender).DataContext)
        {
            case CheckRow { UserSecretsId: { } id }:
                App.Current.ShowWindow<SecretsWindow>().Select(id);
                break;
            case CheckRow { OpensEnvironment: true }:
                ShowEnvironment();
                break;
        }
    }
}

/// <summary>One check as a row. Status is said in words and a glyph, never by colour alone.</summary>
/// <param name="OpensEnvironment">Review opens the environment variables window: the fix for exposed variables.</param>
public sealed record CheckRow(string Name, string StatusText, string Glyph, Brush? Brush, string Detail, string? UserSecretsId = null, bool OpensEnvironment = false)
{
    public string Spoken => $"{Name}: {StatusText}. {Detail}";

    public Visibility ReviewVisibility => UserSecretsId is null && !OpensEnvironment ? Visibility.Collapsed : Visibility.Visible;

    public string ReviewName => UserSecretsId is not null ? Text.Format("Status_ReviewName", UserSecretsId)
        : OpensEnvironment ? Text.Get("Status_ReviewEnvironment") : "";
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
        Checks.Clear();
        ShowState();
        try
        {
            foreach (var check in await Task.Run(() => Doctor.RunAsync(new MachineProbe())))
                Checks.Add(Row(check));
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
        DoctorStatus.Ok => new(check.Name, Text.Get("Status_Ok"), "\uE73E", Brush("SystemFillColorSuccessBrush"), check.Detail, check.UserSecretsId),
        DoctorStatus.Warn => new(check.Name, Text.Get("Status_Warn"), "\uE7BA", Brush("SystemFillColorCautionBrush"), check.Detail, check.UserSecretsId,
            check.Name == Doctor.VariablesCheck),
        _ => new(check.Name, Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), check.Detail, check.UserSecretsId),
    };

    static Brush? Brush(string key) => Application.Current.TryFindResource(key) as Brush;
}
