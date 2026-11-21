using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>
/// Which Tiresias this is: version, where it runs from, since when, and this version's release
/// notes. A development build adds what a tester needs: the commit, build time and configuration.
/// </summary>
public partial class AboutPage : UserControl
{
    public sealed record Fact(string Name, string Value);

    readonly List<Fact> facts = [];

    public AboutPage()
    {
        InitializeComponent();
        var build = AppBuild.Current;
        Heading.Text = Text.Format("About_Heading", Text.Of(build.Label));
        Summary.Text = Text.Get(build.Installed ? "About_Installed" : "About_Development");

        Add("About_Version", build.Version);
        if (build.Development)
        {
            Add("About_Commit", build.Commit ?? Text.Get("About_Unknown"));
            Add("About_Built", $"{AppBuild.BuiltAt:g} ({AppBuild.Configuration})");
        }
        else
            Add("About_Since", AppBuild.Since.ToString("g", CultureInfo.CurrentCulture));
        Add("About_Mode", Text.Get(TrayStatus.Describe(App.Current.Snapshot()).Mode is null ? "Status_ModeNone" : "Status_ModeSolo"));
        Add("About_Folder", build.Folder);
        Add("About_Data", KeyringStore.Directory);
        Add("About_Runtime", $"{RuntimeInformation.FrameworkDescription}, {RuntimeInformation.ProcessArchitecture}");
        Add("About_Windows", Environment.OSVersion.VersionString);
        Facts.ItemsSource = facts;

        NotesHeading.Text = build.Installed ? Text.Format("About_NotesHeading", build.Version) : Text.Get("About_NotesUnreleased");
        Notes.Text = AppBuild.Notes() ?? Text.Get("About_NoNotes");

        // A development build never registers itself: its folder goes stale with the next build.
        StartWithWindowsBox.IsChecked = StartWithWindows.IsOn;
        StartWithWindowsBox.IsEnabled = build.Installed;
        StartWithWindowsNote.Text = Text.Get(build.Installed ? "Status_StartWithWindowsNote" : "Status_StartWithWindowsDev");

        PageButton.Content = Text.Get(build.Installed ? "About_ReleasePage" : "About_CommitPage");
        PageButton.Visibility = build.Installed || AppBuild.CommitPage is not null ? Visibility.Visible : Visibility.Collapsed;

        Loaded += async (_, _) => await ShowAdminTierAsync();
    }

    async Task ShowAdminTierAsync()
    {
        var tier = await Task.Run(AdminClient.FactsAsync);
        AdminTierText.Text = Text.Of(AdminTierCard.Describe(tier));
        var actions = AdminTierCard.Actions(tier.State);
        AdminTierSetUp.Visibility = actions.Contains(AdminTierAction.SetUp) ? Visibility.Visible : Visibility.Collapsed;
        AdminTierUpdate.Visibility = actions.Contains(AdminTierAction.Update) ? Visibility.Visible : Visibility.Collapsed;
        AdminTierRemove.Visibility = actions.Contains(AdminTierAction.Remove) ? Visibility.Visible : Visibility.Collapsed;
    }

    async void OnAdminTierInstall(object sender, RoutedEventArgs e) => await RunAdminTierAsync("install");

    async void OnAdminTierRemove(object sender, RoutedEventArgs e) => await RunAdminTierAsync("remove");

    async Task RunAdminTierAsync(string verb)
    {
        AdminTierSetUp.IsEnabled = AdminTierUpdate.IsEnabled = AdminTierRemove.IsEnabled = false;
        try
        {
            var result = await AdminTierElevation.RunAsync(verb);
            AdminTierOutcome.Text = Text.Of(AdminTierCard.Outcome(result, removing: verb == "remove"));
            await ShowAdminTierAsync();
        }
        finally
        {
            AdminTierSetUp.IsEnabled = AdminTierUpdate.IsEnabled = AdminTierRemove.IsEnabled = true;
        }
    }

    void OnStartWithWindows(object sender, RoutedEventArgs e)
    {
        if (IsLoaded && !StartWithWindows.Set(StartWithWindowsBox.IsChecked == true))
            StartWithWindowsNote.Text = Text.Get("Status_StartWithWindowsFailed");
    }

    void Add(string key, string value) => facts.Add(new(Text.Get(key), value));

    void OnDataFolder(object sender, RoutedEventArgs e) => Desktop.OpenDataFolder();

    void OnGitHub(object sender, RoutedEventArgs e) => Desktop.Open(AppBuild.Repository);

    void OnPage(object sender, RoutedEventArgs e) => Desktop.Open(AppBuild.Current.Installed ? AppBuild.ReleasePage : AppBuild.CommitPage!);

    void OnCopy(object sender, RoutedEventArgs e)
    {
        var text = new StringBuilder().AppendLine(Heading.Text);
        foreach (var fact in facts)
            text.AppendLine(CultureInfo.CurrentCulture, $"{fact.Name}: {fact.Value}");
        if (Window.GetWindow(this) is StatusWindow status)
            text.AppendLine().Append(status.Details());
        try
        {
            Clipboard.SetText(text.ToString());
        }
        catch (COMException)
        {
            // The clipboard is busy; pressing again works.
        }
    }

}
