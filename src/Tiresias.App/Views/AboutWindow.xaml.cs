using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using Tiresias.Agent;

namespace Tiresias.App.Views;

/// <summary>
/// Which Tiresias this is: version, where it runs from, since when, and this version's release
/// notes. A development build adds what a tester needs: the commit, build time and configuration.
/// </summary>
public partial class AboutWindow : Window
{
    public sealed record Fact(string Name, string Value);

    readonly List<Fact> facts = [];

    public AboutWindow()
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
        Add("About_Folder", build.Folder);
        Add("About_Data", KeyringStore.Directory);
        Add("About_Runtime", $"{RuntimeInformation.FrameworkDescription}, {RuntimeInformation.ProcessArchitecture}");
        Add("About_Windows", Environment.OSVersion.VersionString);
        Facts.ItemsSource = facts;

        NotesHeading.Text = build.Installed ? Text.Format("About_NotesHeading", build.Version) : Text.Get("About_NotesUnreleased");
        Notes.Text = AppBuild.Notes() ?? Text.Get("About_NoNotes");

        PageButton.Content = Text.Get(build.Installed ? "About_ReleasePage" : "About_CommitPage");
        PageButton.Visibility = build.Installed || AppBuild.CommitPage is not null ? Visibility.Visible : Visibility.Collapsed;
    }

    void Add(string key, string value) => facts.Add(new(Text.Get(key), value));

    void OnGitHub(object sender, RoutedEventArgs e) => Desktop.Open(AppBuild.Repository);

    void OnPage(object sender, RoutedEventArgs e) => Desktop.Open(AppBuild.Current.Installed ? AppBuild.ReleasePage : AppBuild.CommitPage!);

    void OnCopy(object sender, RoutedEventArgs e)
    {
        var text = new StringBuilder().AppendLine(Heading.Text);
        foreach (var fact in facts)
            text.AppendLine(CultureInfo.CurrentCulture, $"{fact.Name}: {fact.Value}");
        try
        {
            Clipboard.SetText(text.ToString());
        }
        catch (COMException)
        {
            // The clipboard is busy; pressing again works.
        }
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}
