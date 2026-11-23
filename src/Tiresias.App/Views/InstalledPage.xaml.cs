using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;
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

    void OnSearchOnline(object sender, RoutedEventArgs e)
    {
        if (DataContext is InstalledViewModel { Selected: { } row })
            Desktop.Open(InstalledDetails.SearchOnline(row.Name, row.Version).AbsoluteUri);
    }
}

/// <param name="ShortUse">The list's column: a date or a few words.</param>
/// <param name="Use">The details panel's line: what is known of its use, in full.</param>
/// <param name="Icon">The icon its entry names; <c>null</c> shows a generic one.</param>
/// <param name="ProgramFile">The file whose signature the panel checks when the row is selected.</param>
public sealed record InstalledRow(string Name, string Version, string For, string ShortUse, string Use, string Reached, string Folder, ImageSource? Icon,
    string Publisher, string? ProgramFile)
{
    public string Spoken => $"{Name}. {Use}";

    public Visibility IconVisibility => Icon is null ? Visibility.Collapsed : Visibility.Visible;

    public Visibility GenericIconVisibility => Icon is null ? Visibility.Visible : Visibility.Collapsed;
}

public sealed partial class InstalledViewModel : ObservableObject
{
    IReadOnlyList<InstalledProgram> all = [];

    /// <summary>Icons by the entry's <c>DisplayIcon</c>, read with the list, off the UI thread.</summary>
    IReadOnlyDictionary<string, ImageSource> icons = new Dictionary<string, ImageSource>();

    public IReadOnlyList<Choice<bool>> Filters { get; } =
    [
        new(Text.Get("Installed_ShowAll"), false),
        new(Text.Get("Installed_ShowUnused"), true),
    ];

    public ObservableCollection<InstalledRow> Rows { get; } = [];

    [ObservableProperty]
    public partial bool UnusedOnly { get; set; }

    [ObservableProperty]
    public partial string Search { get; set; } = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DetailsVisibility))]
    public partial InstalledRow? Selected { get; set; }

    public Visibility DetailsVisibility => Selected is null ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>Who signed the selected program, checked offline when it is selected: a few files, not the whole list.</summary>
    [ObservableProperty]
    public partial string Signer { get; set; } = "";

    readonly Dictionary<string, string> signers = new(StringComparer.OrdinalIgnoreCase);

    async partial void OnSelectedChanged(InstalledRow? value)
    {
        if (value?.ProgramFile is not { } file)
        {
            Signer = Text.Get("Installed_SignerUnknown");
            return;
        }
        if (!signers.TryGetValue(file, out var text))
        {
            Signer = Text.Get("Installed_SignerChecking");
            var (valid, signer) = await Task.Run(() => MachineProbe.Signature(file));
            var (key, argument) = InstalledDetails.Signer(valid, signer);
            text = signers[file] = argument is null ? Text.Get(key) : Text.Format(key, argument);
        }
        if (Selected == value)
            Signer = text;
    }

    [ObservableProperty]
    public partial string Summary { get; set; } = Text.Get("Installed_Loading");

    [ObservableProperty]
    public partial bool IsEmpty { get; set; }

    public string EmptyText { get; } = Text.Get("Installed_Empty");

    partial void OnUnusedOnlyChanged(bool value) => Apply();

    partial void OnSearchChanged(string value) => Apply();

    [RelayCommand]
    async Task LoadAsync()
    {
        (all, icons) = await Task.Run(() =>
        {
            var probe = new MachineProbe();
            var entries = probe.UninstallEntries().ToArray();
            var runs = probe.ProgramRuns(Doctor.RunsAsked(probe.StartupEntries(), entries, []));
            var programs = Doctor.InstalledPrograms(entries, runs, probe.CredentialUses(), DateTimeOffset.UtcNow);
            Dictionary<string, ImageSource> read = new(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in programs.Select(p => p.Entry).Where(e => e.Icon is not null && e.IconLocation is not null))
                if (!read.ContainsKey(entry.Icon!) && Desktop.SmallIcon(entry.IconLocation!.Value.Path, entry.IconLocation.Value.Index) is { } image)
                    read[entry.Icon!] = image;
            return (programs, (IReadOnlyDictionary<string, ImageSource>)read);
        });
        Apply();
    }

    void Apply()
    {
        var selected = Selected?.Name;
        Rows.Clear();
        foreach (var program in InstalledFilter.Apply(all, Search, UnusedOnly))
            Rows.Add(Row(program, program.Entry.Icon is { } icon ? icons.GetValueOrDefault(icon) : null));
        Selected = Rows.FirstOrDefault(r => r.Name == selected);
        IsEmpty = Rows.Count == 0;
        Summary = Text.Format("Installed_Summary", all.Count, all.Count(p => p.Use == ProgramUse.Unused));
    }

    static InstalledRow Row(InstalledProgram program, ImageSource? icon)
    {
        var date = program.LastOpened?.ToLocalTime().ToString("d", CultureInfo.CurrentCulture);
        var shortUse = program.Use switch
        {
            ProgramUse.Unused => Text.Format("Installed_ShortUnused", date!),
            ProgramUse.Background => Text.Get("Installed_ShortBackground"),
            ProgramUse.NotRecorded => Text.Get("Installed_ShortNotRecorded"),
            _ => date ?? Text.Get("Installed_ShortRecentNoRun"),
        };
        return new(program.Entry.Name, program.Entry.Version ?? "", Text.Get(program.Entry.Machine ? "Installed_ForEveryone" : "Installed_ForYou"),
            shortUse, UseText(program), program.Reached.Count > 0 ? string.Join(", ", program.Reached) : Text.Get("Installed_ReachedNone"),
            program.Entry.Folder ?? Text.Get("Installed_FolderUnknown"), icon, program.Entry.Publisher ?? Text.Get("Installed_PublisherUnknown"),
            program.Entry.ProgramFile);
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
