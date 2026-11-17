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

/// <summary>The status page: the lock state and every <c>tir doctor</c> check, run on this machine.</summary>
public partial class StatusWindow : Window
{
    public StatusWindow()
    {
        InitializeComponent();
        var model = new StatusViewModel();
        DataContext = model;
        Loaded += async (_, _) => await model.RunCommand.ExecuteAsync(null);
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

/// <summary>One check as a row. Status is said in words and a glyph, never by colour alone.</summary>
public sealed record CheckRow(string Name, string StatusText, string Glyph, Brush? Brush, string Detail)
{
    public string Spoken => $"{Name}: {StatusText}. {Detail}";
}

public sealed partial class StatusViewModel : ObservableObject
{
    [ObservableProperty]
    public partial string Headline { get; set; } = "";

    [ObservableProperty]
    public partial string Mode { get; set; } = "";

    [ObservableProperty]
    public partial bool IsRunning { get; set; }

    public ObservableCollection<CheckRow> Checks { get; } = [];

    [RelayCommand]
    async Task RunAsync()
    {
        IsRunning = true;
        Checks.Clear();
        var view = TrayStatus.Describe(App.Current.Snapshot());
        Headline = Text.Of(view.Headline);
        Mode = view.Mode is null ? Text.Get("Status_ModeNone") : Text.Get("Status_ModeSolo");
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
        DoctorStatus.Ok => new(check.Name, Text.Get("Status_Ok"), "\uE73E", Brush("SystemFillColorSuccessBrush"), check.Detail),
        DoctorStatus.Warn => new(check.Name, Text.Get("Status_Warn"), "\uE7BA", Brush("SystemFillColorCautionBrush"), check.Detail),
        _ => new(check.Name, Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), check.Detail),
    };

    static Brush? Brush(string key) => Application.Current.TryFindResource(key) as Brush;
}
