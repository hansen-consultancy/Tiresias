using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Windows;
using Tiresias.Agent;
using Tiresias.Client;

namespace Tiresias.App.Views;

/// <summary>A <see cref="ReachGuide"/>'s steps, with each command to copy or, when it needs an administrator, to run as one.</summary>
public partial class GuideWindow : Window
{
    const int ErrorCancelled = 1223;

    readonly string readMore;

    public GuideWindow(string title, IReadOnlyList<GuideStep> steps, string readMore)
    {
        InitializeComponent();
        this.readMore = readMore;
        Title = title;
        Heading.Text = title;
        Steps.ItemsSource = steps.Select((step, i) => new Row(i + 1, step)).ToArray();
    }

    public sealed record Row(int Number, GuideStep Step)
    {
        public string Text => Step.Text;
        public string? Copy => Step.Copy;
        public Visibility CopyVisibility => Step.Copy is null ? Visibility.Collapsed : Visibility.Visible;
        public Visibility AdminVisibility => Step.Admin ? Visibility.Visible : Visibility.Collapsed;
        public string CopyName => Tiresias.App.Text.Format("Guide_CopyName", Number);
    }

    static Row RowOf(object sender) => (Row)((FrameworkElement)sender).DataContext;

    void OnCopy(object sender, RoutedEventArgs e)
    {
        var copy = RowOf(sender).Copy!;
        try
        {
            Clipboard.SetText(copy);
            Say(Tiresias.App.Text.Format("Finding_Copied", copy));
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            Say(Tiresias.App.Text.Format("Finding_CopyFailed", copy));
        }
    }

    void OnRunAdmin(object sender, RoutedEventArgs e)
    {
        var command = RowOf(sender).Copy!;
        if (DemoMode.On)
        {
            Say(Tiresias.App.Text.Get("Guide_DemoNoRun"));
            return;
        }
        // Encoded, so the command's quotes reach PowerShell as written; echoed first, so the window shows what runs.
        var script = $"Write-Host '> {command.Replace("'", "''", StringComparison.Ordinal)}'; {command}";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        try
        {
            using var _ = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoExit -NoProfile -EncodedCommand {encoded}")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            AppLog.Info("guide: ran a step as administrator");
            Say(Tiresias.App.Text.Get("Guide_Ran"));
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            Say(Tiresias.App.Text.Get("Guide_Declined"));
        }
    }

    void OnReadMore(object sender, RoutedEventArgs e) => Desktop.Open(readMore);

    void Say(string text)
    {
        Message.Text = text;
        Message.Visibility = Visibility.Visible;
    }
}
