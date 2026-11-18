using System.Windows;
using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.App.Views;

/// <summary>Shows again what a program needs to use a saved service: the line the setup windows show once, on saving.</summary>
public partial class UsageWindow : Window
{
    public UsageWindow(Service service)
    {
        InitializeComponent();
        var usage = ServiceUsages.For(service);
        Heading.Text = Text.Format("Usage_Heading", service.Slug);
        Snippet.Text = usage.Snippet;
        (Body.Text, Hint.Text) = usage.Kind switch
        {
            ServiceUsageKind.SqlLogin => (Text.Get("Sql_DoneBody"), usage.Write is null ? "" : Text.Get("Sql_DoneWrite")),
            ServiceUsageKind.Raven => (Text.Get("Raven_DoneBody"), Text.Get("Usage_RavenDatabase") + " " + Text.Get("Raven_DoneCode")),
            _ => (Text.Get("Usage_PlaceholderBody"), Text.Format("Usage_PlaceholderHint", service.Slug)),
        };
        if (Hint.Text.Length == 0)
            Hint.Visibility = Visibility.Collapsed;
    }

    void OnCopy(object sender, RoutedEventArgs e) => Clipboard.SetText(Snippet.Text);

    void OnClose(object sender, RoutedEventArgs e) => Close();
}
