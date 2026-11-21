using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.Client;

namespace Tiresias.App.Views;

/// <summary>
/// Restoring with the paper recovery key after the first run: sealed secrets that this PC's Windows
/// Hello can't open (copied from another PC, or sealed before Hello was reset) are given back to it.
/// Excluded from screen capture, since the key is typed here.
/// </summary>
public partial class RecoveryWindow : Window
{
    public RecoveryWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this, evenInDemo: true);
        DataContext = new RecoveryViewModel();
        Loaded += (_, _) => TypedKey.Focus();
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed partial class RecoveryViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreCommand))]
    public partial string TypedKey { get; set; } = "";

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    public partial string Summary { get; set; } = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreCommand))]
    public partial bool IsWorking { get; set; }

    bool CanRestore() => !IsWorking && TypedKey.Trim().Length > 0;

    [RelayCommand(CanExecute = nameof(CanRestore))]
    async Task RestoreAsync()
    {
        Message = Summary = "";
        var typed = PaperKey.Parse(TypedKey);
        if (typed is null)
        {
            Message = Text.Get("FirstRun_RecoveryType_Invalid");
            return;
        }
        IsWorking = true;
        try
        {
            if (!App.Current.Host.Keys.IsUnlocked && !(await App.Current.UnlockAsync(interactive: true)).Ok)
                return;
            var hello = App.Current.Host.Keys.Hello!;
            var summary = await Task.Run(() => RecoveryRestore.Run(typed, hello));
            AppLog.Info($"recovery restore: {summary.Restored} restored, {summary.AlreadyOpen} already open, {summary.NotOpened.Count} not opened, key adopted {summary.KeyAdopted}");
            Summary = Describe(summary);
            TypedKey = "";
        }
        catch (InvalidOperationException e) when (e is not HelloException)
        {
            // A key, but not one that opens anything here: say so in place.
            Message = e.Message;
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException
            or System.Text.Json.JsonException or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            ProblemWindow.Show(e, "recovery restore", retry: () => RestoreCommand.Execute(null));
        }
        finally
        {
            Array.Clear(typed);
            IsWorking = false;
            App.Current.Refresh();
        }
    }

    internal static string Describe(RestoreSummary summary)
    {
        var lines = new List<string> { Text.Format("Recovery_Result", summary.Restored, summary.AlreadyOpen) };
        if (summary.NotOpened.Count > 0)
            lines.Add(Text.Format("Recovery_NotOpened", string.Join(", ", summary.NotOpened)));
        if (summary.KeyAdopted)
            lines.Add(Text.Get("Recovery_KeyAdopted"));
        if (summary.OtherKeyKept)
            lines.Add(Text.Get("Recovery_OtherKeyKept"));
        return string.Join(Environment.NewLine, lines);
    }
}
