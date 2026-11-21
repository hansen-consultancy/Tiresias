using System.Globalization;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>The local audit: the agent's user-secrets decisions and, in solo mode, the broker's log.</summary>
public partial class ActivityPage : UserControl
{
    public ActivityPage()
    {
        InitializeComponent();
        var model = new ActivityViewModel();
        DataContext = model;
        Loaded += (_, _) => Incidents.Visibility = AdminClient.ServiceInstalled() == false ? Visibility.Collapsed : Visibility.Visible;
        Loaded += async (_, _) => await model.LoadCommand.ExecuteAsync(null);
    }

    void OnIncidents(object sender, RoutedEventArgs e) =>
        new ServiceIncidentsWindow { Owner = Window.GetWindow(this) }.ShowDialog();
}

public sealed record Choice<T>(string Label, T Value);

public sealed record ActivityRow(string Time, string Source, string What, string Service, string Who, string Detail);

public sealed partial class ActivityViewModel : ObservableObject
{
    ActivityHistory history = new([], ServiceJournalState.InApp);

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
        new(Text.Get("Activity_SourceLegacyBroker"), ActivitySource.LegacyBroker),
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
        history = await Task.Run(ActivityLog.ReadAll);
        Apply();
    }

    void Apply()
    {
        var shown = ActivityQuery.Filter(history.Entries, new(Search, Outcome, Source, Period), DateTimeOffset.Now);
        Rows.Clear();
        foreach (var e in shown)
            Rows.Add(new(
                e.Time.ToLocalTime().ToString("g", CultureInfo.CurrentCulture),
                Sources.First(s => s.Value == e.Source).Label,
                Text.Of(ActivityQuery.Describe(e.Kind)),
                e.Service ?? "",
                e.Process ?? e.Consumer ?? "",
                string.Join("  ", new[] { e.Method, e.Path, e.Status?.ToString(CultureInfo.InvariantCulture), e.Reason }.Where(s => !string.IsNullOrEmpty(s)))));
        IsEmpty = shown.Count == 0;
        var notice = history.ServiceJournal switch
        {
            ServiceJournalState.Stopped => Text.Get("Activity_ServiceStopped"),
            ServiceJournalState.Unavailable => Text.Get("Activity_ServiceUnavailable"),
            ServiceJournalState.Invalid => Text.Get("Activity_ServiceInvalid"),
            _ => null,
        };
        EmptyText = notice ?? Text.Get(history.Entries.Count == 0 ? "Activity_EmptyNone" : "Activity_EmptyFiltered");
        var count = shown.Count == ActivityQuery.Limit ? Text.Format("Activity_SummaryLimit", shown.Count) : Text.Format("Activity_Summary", shown.Count, history.Entries.Count);
        Summary = notice is not null && !IsEmpty ? $"{count}  {notice}" : count;
    }
}
