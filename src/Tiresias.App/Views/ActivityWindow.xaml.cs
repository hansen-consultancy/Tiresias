using System.Globalization;
using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>The local audit: the agent's user-secrets decisions and, in solo mode, the broker's log.</summary>
public partial class ActivityWindow : Window
{
    public ActivityWindow()
    {
        InitializeComponent();
        var model = new ActivityViewModel();
        DataContext = model;
        Loaded += async (_, _) => await model.LoadCommand.ExecuteAsync(null);
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed record Choice<T>(string Label, T Value);

public sealed record ActivityRow(string Time, string What, string Service, string Who, string Detail);

public sealed partial class ActivityViewModel : ObservableObject
{
    IReadOnlyList<ActivityEntry> all = [];

    public IReadOnlyList<Choice<ActivityOutcome>> Outcomes { get; } =
    [
        new(Text.Get("Activity_OutcomeAll"), ActivityOutcome.All),
        new(Text.Get("Activity_OutcomeAllowed"), ActivityOutcome.Allowed),
        new(Text.Get("Activity_OutcomeDenied"), ActivityOutcome.Denied),
    ];

    public IReadOnlyList<Choice<ActivitySource?>> Sources { get; } =
    [
        new(Text.Get("Activity_SourceAll"), null),
        new(Text.Get("Activity_SourceUserSecrets"), ActivitySource.UserSecrets),
        new(Text.Get("Activity_SourceBroker"), ActivitySource.Broker),
    ];

    public IReadOnlyList<Choice<ActivityPeriod>> Periods { get; } =
    [
        new(Text.Get("Activity_PeriodToday"), ActivityPeriod.Today),
        new(Text.Get("Activity_PeriodWeek"), ActivityPeriod.Week),
        new(Text.Get("Activity_PeriodAll"), ActivityPeriod.All),
    ];

    public ObservableCollection<ActivityRow> Rows { get; } = [];

    [ObservableProperty]
    public partial string Search { get; set; } = "";

    [ObservableProperty]
    public partial ActivityOutcome Outcome { get; set; } = ActivityOutcome.All;

    [ObservableProperty]
    public partial ActivitySource? Source { get; set; }

    [ObservableProperty]
    public partial ActivityPeriod Period { get; set; } = ActivityPeriod.Week;

    [ObservableProperty]
    public partial string Summary { get; set; } = "";

    [ObservableProperty]
    public partial bool IsEmpty { get; set; }

    [ObservableProperty]
    public partial string EmptyText { get; set; } = "";

    partial void OnSearchChanged(string value) => Apply();

    partial void OnOutcomeChanged(ActivityOutcome value) => Apply();

    partial void OnSourceChanged(ActivitySource? value) => Apply();

    partial void OnPeriodChanged(ActivityPeriod value) => Apply();

    [RelayCommand]
    async Task LoadAsync()
    {
        all = await Task.Run(() => Read(AgentHost.ActivityPath, ActivitySource.UserSecrets).Concat(Read(SoloBroker.AuditPath, ActivitySource.Broker)).ToArray());
        Apply();
    }

    void Apply()
    {
        var shown = ActivityQuery.Filter(all, new(Search, Outcome, Source, Period), DateTimeOffset.Now);
        Rows.Clear();
        foreach (var e in shown)
            Rows.Add(new(
                e.Time.ToLocalTime().ToString("g", CultureInfo.CurrentCulture),
                Text.Of(ActivityQuery.Describe(e.Kind)),
                e.Service ?? "",
                e.Process ?? e.Consumer ?? "",
                string.Join("  ", new[] { e.Method, e.Path, e.Status?.ToString(CultureInfo.InvariantCulture), e.Reason }.Where(s => !string.IsNullOrEmpty(s)))));
        IsEmpty = shown.Count == 0;
        EmptyText = Text.Get(all.Count == 0 ? "Activity_EmptyNone" : "Activity_EmptyFiltered");
        Summary = shown.Count == ActivityQuery.Limit ? Text.Format("Activity_SummaryLimit", shown.Count) : Text.Format("Activity_Summary", shown.Count, all.Count);
    }

    /// <summary>Reads one log, skipping what isn't a record; a missing or locked file reads as empty.</summary>
    static IEnumerable<ActivityEntry> Read(string path, ActivitySource source)
    {
        string[] lines;
        try
        {
            if (!File.Exists(path))
                return [];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, $"reading {path}");
            return [];
        }
        return lines.Select(l => ActivityQuery.Parse(l, source)).OfType<ActivityEntry>();
    }
}
