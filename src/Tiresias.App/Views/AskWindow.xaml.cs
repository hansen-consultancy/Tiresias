using System.Windows;

namespace Tiresias.App.Views;

/// <summary>
/// The app's message box, in the Fluent theme the other windows use. Buttons say what they do
/// ("Seal", "Don't save") rather than Yes/No, and closing the window is always the cancel answer.
/// </summary>
public partial class AskWindow : Window
{
    bool? answer;

    AskWindow(string? heading, string body, string primary, string? secondary, string? cancel)
    {
        InitializeComponent();
        Heading.Text = heading ?? "";
        Heading.Visibility = heading is null ? Visibility.Collapsed : Visibility.Visible;
        Body.Text = body;
        Primary.Content = primary;
        Secondary.Content = secondary;
        Secondary.Visibility = secondary is null ? Visibility.Collapsed : Visibility.Visible;
        CancelButton.Content = cancel;
        CancelButton.Visibility = cancel is null ? Visibility.Collapsed : Visibility.Visible;
        // With no cancel button, Esc and the close box still answer; they mean "OK".
        if (cancel is null)
            Primary.IsCancel = true;
    }

    /// <summary>Asks and waits.</summary>
    /// <param name="owner">The window it belongs to, or <c>null</c> to centre it on screen.</param>
    /// <param name="safeFirst">Focus starts on cancel, so Enter never confirms something hard to undo.</param>
    /// <returns><c>true</c> for <paramref name="primary"/>, <c>false</c> for <paramref name="secondary"/>, <c>null</c> for cancel or closing.</returns>
    public static bool? Show(Window? owner, string? heading, string body, string primary, string? secondary = null, string? cancel = null, bool safeFirst = false)
    {
        var window = new AskWindow(heading, body, primary, secondary, cancel);
        if (owner is { IsVisible: true })
            window.Owner = owner;
        else
        {
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            window.ShowInTaskbar = true;
            window.Topmost = owner is null;
        }
        window.Loaded += (_, _) => (safeFirst && cancel is not null ? window.CancelButton : window.Primary).Focus();
        window.ShowDialog();
        return window.answer ?? (cancel is null ? true : null);
    }

    /// <summary>A notice with one button.</summary>
    public static void Tell(Window? owner, string? heading, string body) => Show(owner, heading, body, Text.Get("Common_OK"));

    /// <summary>A confirmation: <paramref name="action"/> or Cancel, focus on Cancel.</summary>
    public static bool Confirm(Window? owner, string heading, string body, string action) =>
        Show(owner, heading, body, action, cancel: Text.Get("Common_Cancel"), safeFirst: true) == true;

    void OnPrimary(object sender, RoutedEventArgs e)
    {
        answer = true;
        Close();
    }

    void OnSecondary(object sender, RoutedEventArgs e)
    {
        answer = false;
        Close();
    }
}
