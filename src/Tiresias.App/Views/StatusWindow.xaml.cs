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
        Closed += (_, _) => App.Current.Host.StateChanged -= OnAgentStateChanged;
    }

    void OnAgentStateChanged() => Dispatcher.BeginInvoke(model.Refresh);

    void OnClose(object sender, RoutedEventArgs e) => Close();

    void OnSecrets(object sender, RoutedEventArgs e) => App.Current.ShowWindow<SecretsWindow>();

    void OnServices(object sender, RoutedEventArgs e) => App.Current.ShowWindow<ServicesWindow>();

    /// <summary>Opens the secrets editor on the row's project: the fix for a user-secrets line.</summary>
    void OnReview(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is CheckRow { UserSecretsId: { } id })
            App.Current.ShowWindow<SecretsWindow>().Select(id);
    }
}

/// <summary>One check as a row. Status is said in words and a glyph, never by colour alone.</summary>
public sealed record CheckRow(string Name, string StatusText, string Glyph, Brush? Brush, string Detail, string? UserSecretsId = null)
{
    public string Spoken => $"{Name}: {StatusText}. {Detail}";

    public Visibility ReviewVisibility => UserSecretsId is null ? Visibility.Collapsed : Visibility.Visible;

    public string ReviewName => UserSecretsId is null ? "" : Text.Format("Status_ReviewName", UserSecretsId);
}

public sealed partial class StatusViewModel : ObservableObject
{
    [ObservableProperty]
    public partial string Headline { get; set; } = "";

    [ObservableProperty]
    public partial string Mode { get; set; } = "";

    [ObservableProperty]
    public partial bool IsRunning { get; set; }

    [ObservableProperty]
    public partial string LockLabel { get; set; } = "";

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
        if (rerun)
        {
            rerun = false;
            await RunAsync();
        }
    }

    [RelayCommand]
    void Copy()
    {
        var sb = new StringBuilder().AppendLine(Headline).AppendLine(Mode);
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
        DoctorStatus.Warn => new(check.Name, Text.Get("Status_Warn"), "\uE7BA", Brush("SystemFillColorCautionBrush"), check.Detail, check.UserSecretsId),
        _ => new(check.Name, Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), check.Detail, check.UserSecretsId),
    };

    static Brush? Brush(string key) => Application.Current.TryFindResource(key) as Brush;
}
