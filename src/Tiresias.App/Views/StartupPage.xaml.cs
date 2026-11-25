using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App.Views;

/// <summary>
/// Everything that starts without being opened (docs/attack-surface.md, <b>Startup</b>): the Run
/// keys, the Startup folder and log-on scheduled tasks, with the installed app each belongs to.
/// Turning an entry off keeps the program; Settings, Apps, Startup turns it back on.
/// </summary>
public partial class StartupPage : UserControl
{
    public StartupPage()
    {
        InitializeComponent();
        var model = new StartupViewModel();
        DataContext = model;
        Loaded += async (_, _) => await model.LoadCommand.ExecuteAsync(null);
    }

    void OnOpenSettings(object sender, RoutedEventArgs e) => Desktop.Open("ms-settings:startupapps");

    void OnReveal(object sender, RoutedEventArgs e)
    {
        if (DataContext is StartupViewModel { Selected.Entry.Path: { } path })
            Desktop.Reveal(path);
    }

    async void OnTurnOff(object sender, RoutedEventArgs e)
    {
        if (DataContext is not StartupViewModel { Selected: { TurnOff: { } startup } } model
            || !AskWindow.Confirm(Window.GetWindow(this), Text.Format("Finding_DisableStartupHeading", startup.Name), Text.Get("Finding_DisableStartupBody"),
                Text.Get("Finding_TurnOff")))
            return;
        if (Desktop.DisableStartup(startup))
            await model.LoadCommand.ExecuteAsync(null);
        else
            AskWindow.Show(Window.GetWindow(this), null, Text.Format("Finding_RemoveFailed", startup.Name, startup.Instruction), Text.Get("Common_OK"));
    }
}

/// <param name="Mark">What its program's signature says (<see cref="ProgramMarks"/>).</param>
/// <param name="TurnOff">How the app turns it off itself; <c>null</c> when it is off, or needs Settings.</param>
public sealed record StartupRow(StartupEntry Entry, string App, string From, string State, string Opened, string Reached, ProgramMark Mark, DisableStartup? TurnOff)
{
    public string Name => Entry.Name;

    public string Program => Entry.Path ?? Text.Get("Startup_ProgramUnknown");

    public string Spoken => string.Join(". ", new[] { Name, Entry.On ? null : Text.Get("Startup_OffTip"), InstalledRow.MarkTip(Mark), App }.OfType<string>());

    public string Signer => (Entry.Signed, Mark) switch
    {
        (_, ProgramMark.BuiltByYou) => Text.Get("Program_NotSignedBuiltByYou"),
        (true, _) => Text.Get("Startup_Signed"),
        (false, _) => Text.Get("Installed_NotSigned"),
        _ => Text.Get("Installed_SignerUnknown"),
    };

    public Visibility OffVisibility => Entry.On ? Visibility.Collapsed : Visibility.Visible;

    public Visibility UnsignedVisibility => Mark == ProgramMark.Unsigned ? Visibility.Visible : Visibility.Collapsed;

    public Visibility BuiltByYouVisibility => Mark == ProgramMark.BuiltByYou ? Visibility.Visible : Visibility.Collapsed;

    public Visibility TurnOffVisibility => TurnOff is null ? Visibility.Collapsed : Visibility.Visible;

    public Visibility RevealVisibility => Entry.Path is { } path && System.IO.Path.IsPathFullyQualified(path) ? Visibility.Visible : Visibility.Collapsed;
}

public sealed partial class StartupViewModel : ObservableObject
{
    IReadOnlyList<StartupProgram> all = [];

    bool developerTools;

    public IReadOnlyList<Choice<StartupView>> Filters { get; } =
    [
        new(Text.Get("Installed_ShowAll"), StartupView.All),
        new(Text.Get("Startup_ShowNotFromApp"), StartupView.NotFromApp),
        new(Text.Get("Installed_ShowUnsigned"), StartupView.Unsigned),
        new(Text.Get("Startup_ShowOff"), StartupView.Off),
    ];

    public ObservableCollection<StartupRow> Rows { get; } = [];

    [ObservableProperty]
    public partial StartupView View { get; set; }

    [ObservableProperty]
    public partial string Search { get; set; } = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DetailsVisibility))]
    public partial StartupRow? Selected { get; set; }

    public Visibility DetailsVisibility => Selected is null ? Visibility.Collapsed : Visibility.Visible;

    [ObservableProperty]
    public partial string Summary { get; set; } = Text.Get("Installed_Loading");

    [ObservableProperty]
    public partial bool IsEmpty { get; set; }

    public string EmptyText { get; } = Text.Get("Startup_Empty");

    partial void OnViewChanged(StartupView value) => Apply();

    partial void OnSearchChanged(string value) => Apply();

    ProgramMark Mark(StartupEntry entry) => ProgramMarks.Of(entry.Signed, entry.BuiltByYou, developerTools);

    [RelayCommand]
    async Task LoadAsync()
    {
        (all, developerTools) = await Task.Run(() =>
        {
            var probe = new MachineProbe();
            var startup = MachineProbe.AllStartupEntries().ToArray();
            var installed = probe.UninstallEntries().ToArray();
            var runs = probe.ProgramRuns(Doctor.RunsAsked(startup, [], []));
            return (Doctor.StartupPrograms(startup, installed, runs, probe.CredentialUses(), DateTimeOffset.UtcNow), DeveloperSignals.View().Shown);
        });
        Apply();
    }

    void Apply()
    {
        var selected = Selected?.Entry;
        Rows.Clear();
        foreach (var program in StartupFilter.Apply(all, Search, View, Mark))
            Rows.Add(Row(program));
        Selected = Rows.FirstOrDefault(r => r.Entry == selected) ?? Rows.FirstOrDefault(r => selected is not null && r.Name == selected.Name && r.Entry.Where == selected.Where);
        IsEmpty = Rows.Count == 0;
        Summary = Text.Format("Startup_Summary", all.Count, all.Count(p => p.App is null), all.Count(p => Mark(p.Entry) == ProgramMark.Unsigned),
            all.Count(p => !p.Entry.On));
    }

    StartupRow Row(StartupProgram program)
    {
        var entry = program.Entry;
        var from = entry.Where switch
        {
            StartupEntry.RunKey => Text.Get("Startup_FromRunKey"),
            StartupEntry.MachineRunKey => Text.Get("Startup_FromMachineRunKey"),
            StartupEntry.StartupFolder => Text.Get("Startup_FromFolder"),
            _ => Text.Get("Startup_FromTask"),
        };
        return new(entry, program.App ?? Text.Get("Startup_NotFromApp"), from, Text.Get(entry.On ? "Startup_StateOn" : "Startup_StateOff"),
            program.LastOpened?.ToLocalTime().ToString("d", CultureInfo.CurrentCulture) ?? Text.Get("Startup_OpenedUnknown"),
            program.Reached.Count > 0 ? string.Join(", ", program.Reached) : Text.Get("Installed_ReachedNone"),
            Mark(entry), StartupFilter.TurnOff(entry));
    }
}
