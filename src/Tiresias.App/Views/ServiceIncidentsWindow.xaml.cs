using System.Globalization;
using System.Windows;
using Tiresias.AdminTier;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

public partial class ServiceIncidentsWindow : Window
{
    long through;

    public ServiceIncidentsWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await LoadHistoryAsync();
    }

    async void OnRefresh(object sender, RoutedEventArgs e) => await LoadHistoryAsync();

    async void OnReview(object sender, RoutedEventArgs e)
    {
        Review.IsEnabled = Refresh.IsEnabled = false;
        var result = await AdminTierElevation.RunAsync("review-incidents", through.ToString(CultureInfo.InvariantCulture));
        await LoadHistoryAsync();
        if (result is not AdminSetupResult.Done)
            Status.Text = Text.Get("AdminIncidents_ReviewIncomplete");
    }

    async Task LoadHistoryAsync()
    {
        Review.IsEnabled = Refresh.IsEnabled = false;
        var page = await AdminIncidents.HistoryAsync();
        Refresh.IsEnabled = true;
        if (page is null)
        {
            History.ItemsSource = null;
            Status.Text = Text.Get("AdminIncidents_Unavailable");
            return;
        }
        var rows = page.Events.Reverse().Select(e => new IncidentRow(e, e.Id <= page.ReviewedThrough)).ToArray();
        History.ItemsSource = rows;
        through = page.Events.Count > 0 ? page.Events[^1].Id : 0;
        Review.IsEnabled = through > page.ReviewedThrough;
        Status.Text = Text.Format("AdminIncidents_Count", rows.Length, rows.Count(r => !r.Reviewed));
    }
}

/// <summary>An admin-tier incident as the window's table and details panel show it.</summary>
public sealed record IncidentRow(AdminEvent Event, bool Reviewed)
{
    public string Time => Event.Hit.At.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);

    public string Program => Event.Hit.Program ?? Text.Get("Consent_ProgramUnknown");

    public string? Detail => new DecoyTouch(Event.Hit, Event.Parents, Event.Routine, Event.Frozen).Record().Reason;

    public IReadOnlyList<DetailField> Details =>
    [
        new(Text.Get("Activity_ColTime"), Event.Hit.At.ToLocalTime().ToString("G", CultureInfo.CurrentCulture)),
        new(Text.Get("Activity_ColWho"), new DecoyTouch(Event.Hit, Event.Parents).Process ?? Program),
        new(Text.Get("AdminIncidents_Where"), Event.Hit.Endpoint),
        new(Text.Get("Activity_ColDetail"), Detail ?? ""),
        new(Text.Get("AdminIncidents_Reviewed"), Text.Get(Reviewed ? "Common_Yes" : "Common_No")),
    ];
}
