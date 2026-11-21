using System.Windows;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Protocol;

namespace Tiresias.App.Views;

/// <summary>
/// <b>Add a webhook</b> (docs/alerts.md, phase 2): a sealed save of <c>alerts.json</c> with the unlocked
/// Windows Hello wrapper. The first sink also asks for the machine label. Kept out of screen capture:
/// the URL and header can be credentials.
/// </summary>
public partial class AlertWebhookWindow : Window
{
    static readonly AlertSeverity[] Thresholds = [AlertSeverity.Critical, AlertSeverity.High, AlertSeverity.Warning, AlertSeverity.Info];

    readonly bool needsMachine;

    public AlertWebhookWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        needsMachine = App.Current.Alerts.Center.Config is null;
        MachineField.Visibility = needsMachine ? Visibility.Visible : Visibility.Collapsed;
        ThresholdBox.ItemsSource = new[] { Text.Get("Alerts_Critical"), Text.Get("Alerts_High"), Text.Get("Alerts_Warning"), Text.Get("Alerts_Info") };
        ThresholdBox.SelectedIndex = 1;
        Loaded += (_, _) => (needsMachine ? MachineBox : IdBox).Focus();
    }

    /// <summary>The sink saved, once the dialog returns <c>true</c>.</summary>
    public string? AddedId { get; private set; }

    async void OnSave(object sender, RoutedEventArgs e)
    {
        var existing = App.Current.Alerts.Center.Config?.Sinks.Select(s => s.Id) ?? [];
        var (sink, problem) = AlertsCard.Build(needsMachine, MachineBox.Text, IdBox.Text, UrlBox.Text, HeaderNameBox.Text, HeaderValueBox.Password,
            Thresholds[Math.Max(0, ThresholdBox.SelectedIndex)], TrustedBox.IsChecked == true, existing);
        if (problem is not null)
        {
            Message.Text = Text.Of(problem);
            return;
        }
        if (App.Current.Host.Keys.Hello is not { } hello)
        {
            Message.Text = Text.Get("Alerts_Locked");
            return;
        }
        SaveButton.IsEnabled = false;
        try
        {
            var machine = needsMachine ? MachineBox.Text.Trim() : null;
            await Task.Run(() => App.Current.Alerts.Add(machine, sink!, hello));
            AddedId = sink!.Id;
            DialogResult = true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or IOException or UnauthorizedAccessException
            or System.Security.Cryptography.CryptographicException)
        {
            // The exception's text names no URL or header (AlertsConfig and the store never quote them); the log keeps the details.
            AppLog.Error(ex, "alerts: adding a webhook");
            Message.Text = Text.Format("Alerts_SaveFailed", ex.Message);
            SaveButton.IsEnabled = true;
        }
    }
}
