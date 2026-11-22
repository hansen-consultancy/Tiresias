using System.Windows;
using System.Windows.Controls;
using NUnit.Framework;
using Tiresias.App.Views;

namespace Tiresias.App.Tests;

public class StandaloneConsentWindowTests
{
    [Test]
    [Apartment(ApartmentState.STA)]
    public async Task A_console_host_shows_the_shared_consent_window_and_closing_it_denies()
    {
        const string term = "EXAMPLE (global, raw value)";
        string[]? items = null;
        string? command = null;
        bool? showsSessionApproval = null;
        bool? showsIncidentAction = null;
        EventManager.RegisterClassHandler(typeof(ConsentWindow), FrameworkElement.LoadedEvent, new RoutedEventHandler((sender, _) =>
        {
            if (items is not null)
                return;
            var window = (ConsentWindow)sender;
            items = ((ItemsControl)window.FindName("Items")).Items.Cast<string>().ToArray();
            command = ((TextBox)window.FindName("Command")).Text;
            showsSessionApproval = ((Button)window.FindName("AllowSession")).IsVisible;
            showsIncidentAction = ((TextBlock)window.FindName("ReportIncident")).IsVisible;
            window.Dispatcher.InvokeAsync(window.Close);
        }));

        var approved = await StandaloneConsentDialog.AskEnvironmentAsync(["tool.exe", "one\nline"], [term])
            .WaitAsync(TimeSpan.FromSeconds(30));

        Assert.That(approved, Is.False);
        Assert.That(items, Is.EqualTo(new[] { term }));
        Assert.That(command, Is.EqualTo("\"tool.exe\" \"one\\nline\""));
        Assert.That(showsSessionApproval, Is.False);
        Assert.That(showsIncidentAction, Is.False);
    }
}
