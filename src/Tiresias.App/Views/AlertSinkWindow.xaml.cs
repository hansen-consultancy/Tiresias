using System.Windows;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.Protocol;

namespace Tiresias.App.Views;

/// <summary>Which sink <see cref="AlertSinkWindow"/> adds.</summary>
public enum SinkForm
{
    Webhook,
    Ntfy,
    LcdHub,
}

/// <summary>
/// <b>Add a webhook</b>, <b>Add ntfy</b> or <b>Add LcdHub</b> (docs/alerts.md): a sealed save of <c>alerts.json</c> with the
/// unlocked Windows Hello wrapper. The first sink also asks for the machine label. Kept out of screen
/// capture: the URL, header, topic and token can be credentials.
/// </summary>
public partial class AlertSinkWindow : Window
{
    static readonly AlertSeverity[] Thresholds = [AlertSeverity.Critical, AlertSeverity.High, AlertSeverity.Warning, AlertSeverity.Info];

    readonly bool needsMachine;
    readonly SinkForm form;

    public AlertSinkWindow(SinkForm form)
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        this.form = form;
        Title = Heading.Text = Text.Get(form switch { SinkForm.Ntfy => "Alerts_NtfyWindowTitle", SinkForm.LcdHub => "Alerts_LcdHubWindowTitle", _ => "Alerts_WindowTitle" });
        Intro.Text = Text.Get(form switch { SinkForm.Ntfy => "Alerts_NtfyWindowIntro", SinkForm.LcdHub => "Alerts_LcdHubWindowIntro", _ => "Alerts_WindowIntro" });
        WebhookFields.Visibility = form == SinkForm.Webhook ? Visibility.Visible : Visibility.Collapsed;
        NtfyFields.Visibility = form == SinkForm.Ntfy ? Visibility.Visible : Visibility.Collapsed;
        TrustedField.Visibility = form == SinkForm.LcdHub ? Visibility.Collapsed : Visibility.Visible;
        needsMachine = App.Current.Alerts.Center.Config is null;
        MachineField.Visibility = needsMachine ? Visibility.Visible : Visibility.Collapsed;
        ThresholdBox.ItemsSource = new[] { Text.Get("Alerts_Critical"), Text.Get("Alerts_High"), Text.Get("Alerts_Warning"), Text.Get("Alerts_Info") };
        // Defaults per docs/alerts.md: LcdHub warning, the others high.
        ThresholdBox.SelectedIndex = form == SinkForm.LcdHub ? 2 : 1;
        if (form == SinkForm.LcdHub)
            IdBox.Text = "desk";
        Loaded += (_, _) => (needsMachine ? MachineBox : IdBox).Focus();
    }

    /// <summary>The sink saved, once the dialog returns <c>true</c>.</summary>
    public string? AddedId { get; private set; }

    async void OnSave(object sender, RoutedEventArgs e)
    {
        var sinks = App.Current.Alerts.Center.Config?.Sinks ?? [];
        var existing = sinks.Select(s => s.Id);
        var threshold = Thresholds[Math.Max(0, ThresholdBox.SelectedIndex)];
        var trusted = TrustedBox.IsChecked == true;
        var (sink, problem) = form switch
        {
            SinkForm.Ntfy => AlertsCard.BuildNtfy(needsMachine, MachineBox.Text, IdBox.Text, ServerBox.Text, TopicBox.Text, TokenBox.Password, threshold, trusted, existing),
            SinkForm.LcdHub => AlertsCard.BuildLcdHub(needsMachine, MachineBox.Text, IdBox.Text, threshold, sinks),
            _ => ((AlertSink?, Phrase?))AlertsCard.Build(needsMachine, MachineBox.Text, IdBox.Text, UrlBox.Text, HeaderNameBox.Text, HeaderValueBox.Password,
                threshold, trusted, existing),
        };
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
            // The exception's text names no URL, header, topic or token (AlertsConfig and the store never quote them); the log keeps the details.
            AppLog.Error(ex, "alerts: adding a sink");
            Message.Text = Text.Format("Alerts_SaveFailed", ex.Message);
            SaveButton.IsEnabled = true;
        }
    }
}
