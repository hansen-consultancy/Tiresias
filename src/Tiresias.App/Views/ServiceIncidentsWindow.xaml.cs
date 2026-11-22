using System.Globalization;
using System.Windows;
using Tiresias.AdminTier;
using Tiresias.Agent;

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
        var rows = page.Events.Reverse().Select(e => new
        {
            Time = e.Hit.At.ToLocalTime().ToString("g", CultureInfo.CurrentCulture),
            Program = e.Hit.Program ?? Text.Get("Consent_ProgramUnknown"),
            Detail = new DecoyTouch(e.Hit, e.Parents).Record().Reason,
            Reviewed = e.Id <= page.ReviewedThrough
        }).ToArray();
        History.ItemsSource = rows;
        through = page.Events.Count > 0 ? page.Events[^1].Id : 0;
        Review.IsEnabled = through > page.ReviewedThrough;
        Status.Text = Text.Format("AdminIncidents_Count", rows.Length, rows.Count(r => !r.Reviewed));
    }
}
