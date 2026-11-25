using System.Collections.Concurrent;
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

    void OnTrust(object sender, RoutedEventArgs e) => (DataContext as InstalledViewModel)?.ToggleTrust();

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
/// <param name="InstalledOn">The install date, or why it isn't known.</param>
/// <param name="IsNew">Installed in the last <see cref="InstalledFilter.NewDays"/> days.</param>
/// <param name="Mark">What its program file's signature says (<see cref="ProgramMarks"/>).</param>
public sealed record InstalledRow(string Name, string Version, string For, string ShortUse, string Use, string Reached, string Folder, ImageSource? Icon,
    string Publisher, string? ProgramFile, string InstalledOn, bool IsNew, ProgramMark Mark)
{
    public string Spoken => string.Join(". ", new[] { Name, IsNew ? NewTip : null, MarkTip(Mark), Use }.OfType<string>());

    public static string NewTip => Text.Format("Installed_ShowNew", InstalledFilter.NewDays);

    /// <summary>What a mark says, for its tooltip and a screen reader; <c>null</c> for none.</summary>
    public static string? MarkTip(ProgramMark mark) => mark switch
    {
        ProgramMark.Unsigned => Text.Get("Installed_UnsignedTip"),
        ProgramMark.BuiltByYou => Text.Get("Program_BuiltByYouTip"),
        _ => null,
    };

    public Visibility NewVisibility => IsNew ? Visibility.Visible : Visibility.Collapsed;

    public Visibility UnsignedVisibility => Mark == ProgramMark.Unsigned ? Visibility.Visible : Visibility.Collapsed;

    public Visibility BuiltByYouVisibility => Mark == ProgramMark.BuiltByYou ? Visibility.Visible : Visibility.Collapsed;

    public Visibility IconVisibility => Icon is null ? Visibility.Collapsed : Visibility.Visible;

    public Visibility GenericIconVisibility => Icon is null ? Visibility.Visible : Visibility.Collapsed;
}

public sealed partial class InstalledViewModel : ObservableObject
{
    IReadOnlyList<InstalledProgram> all = [];

    /// <summary>Icons by the entry's <c>DisplayIcon</c>, read with the list, off the UI thread.</summary>
    IReadOnlyDictionary<string, ImageSource> icons = new Dictionary<string, ImageSource>();

    public IReadOnlyList<Choice<InstalledView>> Filters { get; } =
    [
        new(Text.Get("Installed_ShowAll"), InstalledView.All),
        new(Text.Get("Installed_ShowUnused"), InstalledView.Unused),
        new(Text.Get("Installed_ShowUnsigned"), InstalledView.Unsigned),
        new(Text.Format("Installed_ShowNew", InstalledFilter.NewDays), InstalledView.New),
        new(Text.Get("Installed_ShowExtensions"), InstalledView.Extensions),
        new(Text.Get("Installed_ShowTools"), InstalledView.Tools),
    ];

    IReadOnlyList<AddOn> extensions = [], tools = [];

    /// <summary>When the global tools were listed; <c>null</c> until read.</summary>
    DateTimeOffset? toolsListed;

    public ObservableCollection<InstalledRow> Rows { get; } = [];

    [ObservableProperty]
    public partial InstalledView View { get; set; }

    [ObservableProperty]
    public partial string Search { get; set; } = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DetailsVisibility))]
    public partial InstalledRow? Selected { get; set; }

    public Visibility DetailsVisibility => Selected is null ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>Who signed the selected program, checked offline: from the scan of the whole list once it has reached the file, else on its own.</summary>
    [ObservableProperty]
    public partial string Signer { get; set; } = "";

    /// <summary>
    /// Each program file's signature and whether it looks like the user's own build, filled by the
    /// scan after the list loads (off the UI thread) and by a selection it hasn't reached.
    /// </summary>
    readonly ConcurrentDictionary<string, (bool? Valid, string? Signer, Publisher? Publisher, bool BuiltByYou)> signatures = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Developer tools show, so an own build is marked as such (read with the list).</summary>
    bool developerTools;

    static (bool? Valid, string? Signer, Publisher? Publisher, bool BuiltByYou) Check(string file)
    {
        var (valid, signer, publisher) = MachineProbe.Signature(file);
        return (valid, signer, publisher, MachineProbe.BuiltByYou(file, valid, signer));
    }

    /// <summary>Non-zero while the scan of the list's signatures runs; each load bumps it, so an older scan's end doesn't count.</summary>
    int scanning;

    /// <summary>The selected program's checked publisher, which the trust line speaks of; <c>null</c> without a valid signature.</summary>
    Publisher? publisher;

    /// <summary>Whether the selected program's publisher is trusted, in words.</summary>
    [ObservableProperty]
    public partial string Trust { get; set; } = "";

    /// <summary>Trust or Stop trusting for the selected program's publisher; empty hides the button.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustButtonVisibility))]
    public partial string TrustButton { get; set; } = "";

    public Visibility TrustButtonVisibility => TrustButton.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    void ShowTrust(Publisher? value)
    {
        publisher = value;
        var (key, argument, button) = InstalledDetails.Trust(value, DismissalStore.Load());
        Trust = argument is null ? Text.Get(key) : Text.Format(key, argument);
        TrustButton = button is null ? "" : Text.Format(button, value!.Name);
    }

    /// <summary>Trusts the selected program's publisher, or stops: Home re-sorts its findings when shown again.</summary>
    public void ToggleTrust()
    {
        if (publisher is not { } current)
            return;
        try
        {
            DismissalStore.Update(d => d.Trusts(current) ? d.Distrust(current.Key) : d.Trust(current, DateTimeOffset.Now));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "saving a trusted publisher");
        }
        ShowTrust(current);
    }

    async partial void OnSelectedChanged(InstalledRow? value)
    {
        if (value?.ProgramFile is not { } file)
        {
            Signer = Text.Get("Installed_SignerUnknown");
            ShowTrust(null);
            return;
        }
        if (!signatures.TryGetValue(file, out var signature))
        {
            Signer = Text.Get("Installed_SignerChecking");
            signature = signatures[file] = await Task.Run(() => Check(file));
        }
        var (key, argument) = InstalledDetails.Signer(signature.Valid, signature.Signer, ProgramMarks.Of(signature.Valid, signature.BuiltByYou, developerTools));
        if (Selected != value)
            return;
        Signer = argument is null ? Text.Get(key) : Text.Format(key, argument);
        ShowTrust(signature.Publisher);
    }

    ProgramMark Mark(string file) => signatures.TryGetValue(file, out var s) ? ProgramMarks.Of(s.Valid, s.BuiltByYou, developerTools) : ProgramMark.None;

    [ObservableProperty]
    public partial string Summary { get; set; } = Text.Get("Installed_Loading");

    [ObservableProperty]
    public partial bool IsEmpty { get; set; }

    public string EmptyText { get; } = Text.Get("Installed_Empty");

    partial void OnViewChanged(InstalledView value) => Apply();

    partial void OnSearchChanged(string value) => Apply();

    [RelayCommand]
    async Task LoadAsync()
    {
        (all, icons, developerTools) = await Task.Run(() =>
        {
            var probe = new MachineProbe();
            var entries = probe.UninstallEntries().ToArray();
            var runs = probe.ProgramRuns(Doctor.RunsAsked(probe.StartupEntries(), entries, []));
            var programs = Doctor.InstalledPrograms(entries, runs, probe.CredentialUses(), DateTimeOffset.UtcNow);
            Dictionary<string, ImageSource> read = new(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in programs.Select(p => p.Entry).Where(e => e.Icon is not null && e.IconLocation is not null))
                if (!read.ContainsKey(entry.Icon!) && Desktop.SmallIcon(entry.IconLocation!.Value.Path, entry.IconLocation.Value.Index) is { } image)
                    read[entry.Icon!] = image;
            return (programs, (IReadOnlyDictionary<string, ImageSource>)read, DeveloperSignals.View().Shown);
        });
        signatures.Clear();
        var scan = ++generation;
        scanning = scan;
        Apply();
        var addOns = LoadAddOnsAsync();
        await ScanSignaturesAsync(scan);
        await addOns;
    }

    /// <summary>Extensions and the day's global tools listing, which takes seconds when a day has passed: read after the programs show.</summary>
    async Task LoadAddOnsAsync()
    {
        (extensions, tools, toolsListed) = await Task.Run(() =>
        {
            var probe = new MachineProbe();
            var snapshot = ToolInventory.Current();
            return (InstalledAddOns.Extensions(probe.Extensions(), probe.CredentialUses(), DateTimeOffset.UtcNow), InstalledAddOns.Tools(snapshot), (DateTimeOffset?)snapshot.At);
        });
        Apply();
    }

    int generation;

    /// <summary>
    /// Checks every program file's signature, a few at a time, so Unsigned can be marked and picked;
    /// an offline check takes a moment, so the list shows first and the marks follow.
    /// </summary>
    async Task ScanSignaturesAsync(int scan)
    {
        var files = all.Select(p => p.Entry.ProgramFile).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        await Task.Run(() => Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 4 },
            file => signatures.TryAdd(file, Check(file))));
        if (scan != generation)
            return;
        scanning = 0;
        Apply();
    }

    void Apply()
    {
        var selected = Selected?.Name;
        Rows.Clear();
        if (View is InstalledView.Extensions or InstalledView.Tools)
        {
            var list = View == InstalledView.Extensions ? extensions : tools;
            foreach (var addOn in InstalledAddOns.Filter(list, Search))
                Rows.Add(Row(addOn));
            Selected = Rows.FirstOrDefault(r => r.Name == selected);
            IsEmpty = Rows.Count == 0;
            Summary = View == InstalledView.Extensions
                ? Text.Format("Installed_SummaryExtensions", extensions.Count, extensions.Count(e => e.Reached.Count > 0))
                : toolsListed is { } listed ? Text.Format("Installed_SummaryTools", tools.Count, listed.ToLocalTime().ToString("g", CultureInfo.CurrentCulture))
                : Text.Get("Installed_Loading");
            return;
        }
        var today = DateOnly.FromDateTime(DateTime.Today);
        foreach (var program in InstalledFilter.Apply(all, Search, View, today, Mark))
            Rows.Add(Row(program, program.Entry.Icon is { } icon ? icons.GetValueOrDefault(icon) : null, today));
        Selected = Rows.FirstOrDefault(r => r.Name == selected);
        IsEmpty = Rows.Count == 0;
        Summary = Text.Format("Installed_Summary", all.Count, all.Count(p => p.Use == ProgramUse.Unused))
            + ", " + (scanning != 0 ? Text.Get("Installed_SummaryScanning") : Text.Format("Installed_SummaryUnsigned", all.Count(p => InstalledFilter.IsUnsigned(p.Entry, Mark))))
            + ", " + Text.Format("Installed_SummaryNew", all.Count(p => InstalledFilter.IsNew(p.Entry, today)), InstalledFilter.NewDays);
    }

    InstalledRow Row(InstalledProgram program, ImageSource? icon, DateOnly today)
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
            program.Entry.ProgramFile,
            program.Entry.InstalledOn?.ToString("d", CultureInfo.CurrentCulture) ?? Text.Get("Installed_InstalledOnUnknown"),
            InstalledFilter.IsNew(program.Entry, today), InstalledFilter.Mark(program.Entry, Mark));
    }

    /// <summary>An extension or tool: no file, signature, icon or install date of its own here; "For" names its host or manager.</summary>
    static InstalledRow Row(AddOn addOn)
    {
        var updated = addOn.Updated?.ToLocalTime().ToString("d", CultureInfo.CurrentCulture);
        return new(addOn.Name, addOn.Version ?? "", addOn.In,
            updated is null ? Text.Get("Installed_ShortUpdatedUnknown") : Text.Format("Installed_ShortUpdated", updated),
            updated is null ? Text.Get("Installed_UseAddOnUnknown") : Text.Format("Installed_UseAddOn", updated),
            addOn.Reached.Count > 0 ? string.Join(", ", addOn.Reached) : Text.Get("Installed_ReachedNone"),
            Text.Get("Installed_FolderUnknown"), null, addOn.Publisher ?? Text.Get("Installed_PublisherUnknown"), null,
            Text.Get("Installed_InstalledOnUnknown"), false, ProgramMark.None);
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
