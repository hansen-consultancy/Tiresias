using System.Windows;
using System.Windows.Controls;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>
/// What a left click on the tray icon opens: the lock state with Lock or Unlock, what Home found
/// the last time it checked, and the few places you go from the tray. The right-click menu stays
/// for the rest. Each button closes the flyout through <see cref="Done"/>.
/// </summary>
public partial class TrayFlyout : UserControl
{
    Action? applyUpdate;

    /// <summary>The button locks when locking is offered; otherwise it unlocks.</summary>
    bool locks;

    public TrayFlyout()
    {
        InitializeComponent();
        Build.Text = Text.Of(AppBuild.Current.Label);
    }

    /// <summary>Raised after a button acted, so the tray closes the popup.</summary>
    public event Action? Done;

    /// <summary>Fills the flyout as things are now; asked each time it opens, since the areas read the vault and logs.</summary>
    public void Show(TrayView view, int? findings, IReadOnlySet<HomeArea> areas, string? update, Action? apply)
    {
        Headline.Text = Text.Of(view.Headline);
        Mode.Text = view.Mode is null ? "" : Text.Of(view.Mode);
        Mode.Visibility = view.Mode is null ? Visibility.Collapsed : Visibility.Visible;
        locks = view.CanLock;
        LockButton.Content = Text.Get(locks ? "Tray_Lock" : "Tray_Unlock");
        LockButton.Visibility = view.CanLock || view.CanUnlock ? Visibility.Visible : Visibility.Collapsed;
        FindingsText.Text = findings switch
        {
            1 => Text.Get("Status_SummaryOne"),
            > 1 => Text.Format("Status_SummaryMany", findings),
            _ => "",
        };
        Findings.Visibility = findings > 0 && !view.OfferSetup ? Visibility.Visible : Visibility.Collapsed;
        Setup.Visibility = Visible(view.OfferSetup);
        Add.Visibility = Visible(!view.OfferSetup);
        Open.Visibility = Visible(!view.OfferSetup);
        Secrets.Visibility = Visible(!view.OfferSetup && areas.Contains(HomeArea.UserSecrets));
        Activity.Visibility = Visible(!view.OfferSetup && areas.Contains(HomeArea.Activity));
        applyUpdate = apply;
        UpdateText.Text = update is null ? "" : Text.Format("Tray_UpdateReady", update);
        Update.Visibility = Visible(update is not null && apply is not null);
    }

    static Visibility Visible(bool show) => show ? Visibility.Visible : Visibility.Collapsed;

    void Act(Action action)
    {
        Done?.Invoke();
        action();
    }

    async void OnLock(object sender, RoutedEventArgs e)
    {
        Done?.Invoke();
        if (locks)
            await App.Current.LockAsync();
        else
            await App.Current.UnlockAsync(interactive: true);
    }

    void OnHome(object sender, RoutedEventArgs e) => Act(App.Current.ShowHome);

    void OnAdd(object sender, RoutedEventArgs e) => Act(() => App.Current.ShowWindow<NeedsWindow>());

    void OnSecrets(object sender, RoutedEventArgs e) => Act(() => App.Current.ShowWindow<SecretsWindow>());

    void OnActivity(object sender, RoutedEventArgs e) => Act(() => App.Current.ShowWindow<ActivityWindow>());

    void OnUpdate(object sender, RoutedEventArgs e) => Act(() => applyUpdate?.Invoke());

    void OnQuit(object sender, RoutedEventArgs e) => Act(App.Current.Quit);
}
