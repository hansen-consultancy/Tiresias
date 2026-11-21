using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.Client;

namespace Tiresias.App.Views;

/// <summary>
/// The installed-apps list with what Tiresias knows of each program's use (docs/attack-surface.md,
/// <b>Installed</b>): hygiene, read-only. Uninstalling happens in Settings, which runs the program's
/// own uninstaller.
/// </summary>
public partial class InstalledPage : UserControl
{
    public InstalledPage()
    {
        InitializeComponent();
        var model = new InstalledViewModel();
        DataContext = model;
        Loaded += async (_, _) => await model.LoadCommand.ExecuteAsync(null);
    }

    void OnOpenSettings(object sender, RoutedEventArgs e) => Desktop.Open("ms-settings:appsfeatures");
}

public sealed record InstalledRow(string Name, string Version, string For, string Use, string Reached);

public sealed partial class InstalledViewModel : ObservableObject
{
    IReadOnlyList<InstalledProgram> all = [];

    public IReadOnlyList<Choice<bool>> Filters { get; } =
    [
        new(Text.Get("Installed_ShowAll"), false),
        new(Text.Get("Installed_ShowUnused"), true),
    ];

    public ObservableCollection<InstalledRow> Rows { get; } = [];

    [ObservableProperty]
    public partial bool UnusedOnly { get; set; }

    [ObservableProperty]
    public partial string Summary { get; set; } = Text.Get("Installed_Loading");

    [ObservableProperty]
    public partial bool IsEmpty { get; set; }

    public string EmptyText { get; } = Text.Get("Installed_Empty");

    partial void OnUnusedOnlyChanged(bool value) => Apply();

    [RelayCommand]
    async Task LoadAsync()
    {
        all = await Task.Run(() =>
        {
            var probe = new MachineProbe();
            return Doctor.InstalledPrograms(probe.UninstallEntries(), probe.ProgramRuns(), probe.CredentialUses(), DateTimeOffset.UtcNow);
        });
        Apply();
    }

    void Apply()
    {
        Rows.Clear();
        foreach (var program in all.Where(p => !UnusedOnly || p.Use == ProgramUse.Unused))
            Rows.Add(new(program.Entry.Name, program.Entry.Version ?? "", Text.Get(program.Entry.Machine ? "Installed_ForEveryone" : "Installed_ForYou"),
                UseText(program), string.Join(", ", program.Reached)));
        IsEmpty = Rows.Count == 0;
        Summary = Text.Format("Installed_Summary", all.Count, all.Count(p => p.Use == ProgramUse.Unused));
    }

    static string UseText(InstalledProgram program)
    {
        var date = program.LastOpened?.ToLocalTime().ToString("d", CultureInfo.CurrentCulture);
        return program.Use switch
        {
            ProgramUse.Unused => Text.Format("Installed_UseUnused", date!),
            ProgramUse.Background => Text.Get("Installed_UseBackground"),
            ProgramUse.NotRecorded => Text.Get("Installed_UseNotRecorded"),
            _ => date ?? Text.Get("Installed_UseRecentNoRun"),
        };
    }
}
