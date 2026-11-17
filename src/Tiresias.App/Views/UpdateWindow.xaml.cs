using System.Windows;

namespace Tiresias.App.Views;

/// <summary>What a downloaded update changes (its section of CHANGELOG.md), before the user restarts into it.</summary>
public partial class UpdateWindow : Window
{
    public UpdateWindow(string version, string? notes)
    {
        InitializeComponent();
        Heading.Text = Text.Format("Update_Heading", version);
        Notes.Text = string.IsNullOrWhiteSpace(notes) ? Text.Get("Update_NoNotes") : notes.Trim();
    }

    void OnRestart(object sender, RoutedEventArgs e) => DialogResult = true;
}
