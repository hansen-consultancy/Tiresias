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
        mode = view.Mode is null ? null : Text.Of(view.Mode);
        Mode.Text = mode ?? "";
        Mode.Visibility = mode is null ? Visibility.Collapsed : Visibility.Visible;
        _ = ShowApprovalsAsync();
        locks = view.CanLock;
        LockCircle.SetResourceReference(Border.BackgroundProperty, locks ? "SystemFillColorSuccessBackgroundBrush" : "SubtleFillColorTertiaryBrush");
        LockGlyph.SetResourceReference(TextBlock.ForegroundProperty, locks ? "SystemFillColorSuccessBrush" : "TextFillColorSecondaryBrush");
        LockGlyph.Text = locks ? "\uE785" : "\uE72E";
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

    string? mode;

    /// <summary>Today's approvals under the headline, read off the UI thread; the mode, when there is one, leads.</summary>
    async Task ShowApprovalsAsync()
    {
        var today = await Task.Run(() => ActivityQuery.Today(ActivityLog.ReadAll(), DateTimeOffset.Now));
        var approvals = today.Approvals switch
        {
            0 => Text.Get("Flyout_ApprovalsNone"),
            1 => Text.Get("Flyout_ApprovalsOne"),
            var n => Text.Format("Flyout_ApprovalsMany", n),
        };
        Mode.Text = mode is null ? approvals : $"{mode} \u00b7 {approvals}";
        Mode.Visibility = Visibility.Visible;
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

    void OnSecrets(object sender, RoutedEventArgs e) => Act(() => App.Current.ShowPage<SecretsPage>());

    void OnActivity(object sender, RoutedEventArgs e) => Act(() => App.Current.ShowPage<ActivityPage>());

    void OnUpdate(object sender, RoutedEventArgs e) => Act(() => applyUpdate?.Invoke());

    void OnQuit(object sender, RoutedEventArgs e) => Act(App.Current.Quit);
}
