using System.ComponentModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;
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

    protected override void OnClosing(CancelEventArgs e)
    {
        base.OnClosing(e);
        if (DataContext is RecoveryViewModel { IsWorking: true })
            e.Cancel = true;
    }

    protected override void OnClosed(EventArgs e)
    {
        ((RecoveryViewModel)DataContext).TypedKey = "";
        base.OnClosed(e);
    }
}

public sealed partial class RecoveryViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreCommand))]
    [NotifyPropertyChangedFor(nameof(Fingerprint))]
    public partial string TypedKey { get; set; } = "";

    public string Fingerprint => FingerprintText(TypedKey);

    internal static string FingerprintText(byte[] paper) => Text.Format("Recovery_CompareFingerprint", PaperKey.RecipientFingerprint(paper));

    internal static string FingerprintText(string typed)
    {
        var paper = PaperKey.Parse(typed);
        if (paper is null)
            return "";
        try
        {
            return FingerprintText(paper);
        }
        finally
        {
            Array.Clear(paper);
        }
    }

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
        var text = TypedKey;
        IsWorking = true;
        PaperKeyReading? reading = null;
        try
        {
            reading = await Task.Run(() => RecoveryRestore.Read(text));
            if (reading is null)
            {
                Message = Text.Get("FirstRun_RecoveryType_Invalid");
                return;
            }
            if (!App.Current.Host.Keys.IsUnlocked && !(await App.Current.UnlockAsync(PromptReason.Recovery, interactive: true)).Ok)
                return;
            var hello = App.Current.Host.Keys.Hello!;
            var typed = reading.Key;
            var summary = await Task.Run(() => RecoveryRestore.Run(typed, hello));
            AppLog.Info($"recovery restore: {summary.Restored} restored, {summary.AlreadyOpen} already open, {summary.NotOpened.Count} not opened, key adopted {summary.KeyAdopted}, {reading.Corrections.Count} lookalikes read");
            Summary = Corrected(reading) + Describe(summary);
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
            if (reading is not null)
                Array.Clear(reading.Key);
            IsWorking = false;
            App.Current.Refresh();
        }
    }

    /// <summary>The lookalike letters read the other way, as a line of its own, or nothing.</summary>
    internal static string Corrected(PaperKeyReading reading) => reading.Corrections.Count == 0 ? ""
        : Text.Format("Recovery_LookalikesRead", string.Join(", ", reading.Corrections.Select(c => Text.Format("Recovery_LookalikeRead", c.Group, c.Typed, c.Read))))
            + Environment.NewLine;

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
