using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CommunityToolkit.Mvvm.Input;
using H.NotifyIcon;
using Microsoft.Win32;
using Tiresias.App.Logic;
using Tiresias.App.Views;

namespace Tiresias.App;

/// <summary>
/// The notification-area icon. A left click opens the <see cref="TrayFlyout"/> (or setup, until it is
/// finished); the right-click menu keeps the lock state (plus "Solo"), Unlock or Lock, Home, Add...
/// (<i>What do you need?</i>) and Activity once anything is recorded; every other window is reached
/// from those. The icon follows the taskbar's light or dark theme, and a development build's icon has
/// an orange corner and a menu line saying which build it is. Findings Home hasn't shown yet
/// (<see cref="FindingWatch"/>) put a dot on the icon and their count on Status... and the tooltip.
/// </summary>
sealed class TrayController : IDisposable
{
    readonly App app;
    readonly TaskbarIcon icon;
    readonly MenuItem build = new() { IsEnabled = false, Header = Text.Of(AppBuild.Current.Label) };
    readonly MenuItem headline = new() { IsEnabled = false };
    readonly MenuItem mode = new() { IsEnabled = false };
    readonly MenuItem unlock = new() { Header = Text.Get("Tray_Unlock") };
    readonly MenuItem lockItem = new() { Header = Text.Get("Tray_Lock") };
    readonly MenuItem setup = new() { Header = Text.Get("Tray_FinishSetup") };
    readonly MenuItem update = new() { Visibility = Visibility.Collapsed };
    readonly Separator updateSeparator = new() { Visibility = Visibility.Collapsed };
    readonly TrayFlyout flyout = new();
    readonly MenuItem status;
    TrayView? view;
    string? updateVersion;
    Action? updateApply;

    public TrayController(App app)
    {
        this.app = app;
        unlock.Click += async (_, _) => await app.UnlockAsync(interactive: true);
        lockItem.Click += async (_, _) => await app.LockAsync();
        setup.Click += (_, _) => app.ShowWindow<FirstRunWindow>();
        status = Item("Tray_Status", () => app.ShowWindow<StatusWindow>());
        var add = Item("Tray_Add", () => app.ShowWindow<NeedsWindow>());
        var activity = Item("Tray_Activity", () => app.ShowPage<ActivityPage>());
        var quit = Item("Tray_Quit", app.Quit);

        icon = new TaskbarIcon
        {
            ToolTipText = Text.Get("App_Name"),
            ContextMenu = new ContextMenu(),
            LeftClickCommand = new RelayCommand(OnLeftClick),
            NoLeftClickDelay = true,
            TrayPopup = flyout,
            PopupActivation = H.NotifyIcon.Core.PopupActivationMode.LeftClick,
        };
        flyout.Done += icon.CloseTrayPopup;
        icon.PreviewTrayPopupOpen += OnPreviewFlyout;
        if (AppBuild.Current.Development)
        {
            icon.ContextMenu.Items.Add(build);
            icon.ContextMenu.Items.Add(new Separator());
        }
        foreach (var item in new Control[] { headline, mode, unlock, lockItem, setup })
            icon.ContextMenu.Items.Add(item);
        icon.ContextMenu.Items.Add(new Separator());
        icon.ContextMenu.Items.Add(status);
        icon.ContextMenu.Items.Add(add);
        icon.ContextMenu.Items.Add(activity);
        icon.ContextMenu.Items.Add(updateSeparator);
        icon.ContextMenu.Items.Add(update);
        icon.ContextMenu.Items.Add(new Separator());
        icon.ContextMenu.Items.Add(quit);
        AutomationName(icon.ContextMenu, "App_Name");
        // Asked when the menu opens, not on every state change: it reads the vault and the logs.
        icon.ContextMenu.Opened += (_, _) =>
            activity.Visibility = Home.Areas([]).Contains(HomeArea.Activity) ? Visibility.Visible : Visibility.Collapsed;

        UpdateIcon();
        SystemEvents.UserPreferenceChanged += OnPreferenceChanged;
        FindingWatch.Changed += OnFindingsChanged;
        icon.ForceCreate(enablesEfficiencyMode: false);
    }

    /// <summary>Setup, until it is finished; after that a left click opens the flyout instead.</summary>
    void OnLeftClick()
    {
        if (view is null or { OfferSetup: true })
            app.ShowHome();
    }

    /// <summary>Fills the flyout as things are now, or keeps it closed while setup is unfinished.</summary>
    void OnPreviewFlyout(object sender, RoutedEventArgs e)
    {
        if (view is null or { OfferSetup: true })
        {
            e.Handled = true;
            return;
        }
        flyout.Show(view, Home.LastFindings, Home.Areas([]), updateVersion, updateApply);
    }

    public void Refresh(AgentSnapshot snapshot)
    {
        var view = this.view = TrayStatus.Describe(snapshot);
        headline.Header = Text.Of(view.Headline);
        mode.Header = view.Mode is null ? null : Text.Of(view.Mode);
        mode.Visibility = view.Mode is null ? Visibility.Collapsed : Visibility.Visible;
        unlock.Visibility = view.CanUnlock ? Visibility.Visible : Visibility.Collapsed;
        lockItem.Visibility = view.CanLock ? Visibility.Visible : Visibility.Collapsed;
        setup.Visibility = view.OfferSetup ? Visibility.Visible : Visibility.Collapsed;
        ShowTooltip();
    }

    void ShowTooltip()
    {
        if (view is null)
            return;
        var unseen = FindingWatch.NewCount;
        icon.ToolTipText = $"{Text.Get("App_Name")} - {Text.Of(view.Tooltip)}"
            + (unseen > 0 ? $"{Environment.NewLine}{Text.Format("Tray_NewFindings", unseen)}" : "")
            + (AppBuild.Current.Development ? $"{Environment.NewLine}{Text.Of(AppBuild.Current.Label)}" : "");
    }

    void OnFindingsChanged()
    {
        var unseen = FindingWatch.NewCount;
        status.Header = unseen > 0 ? Text.Format("Tray_StatusNew", unseen) : Text.Get("Tray_Status");
        UpdateIcon();
        ShowTooltip();
    }

    /// <summary>Offers "Update available - restart to apply" in the menu; <c>null</c> hides it.</summary>
    public void OfferUpdate(string? version, Action? apply)
    {
        var show = version is not null && apply is not null;
        (updateVersion, updateApply) = show ? (version, apply) : (null, null);
        update.Visibility = updateSeparator.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        if (!show)
            return;
        update.Header = Text.Format("Tray_UpdateReady", version);
        update.Click -= OnUpdateClick;
        update.Tag = apply;
        update.Click += OnUpdateClick;
    }

    public void Notify(string title, string message) => icon.ShowNotification(title, message);

    void OnUpdateClick(object sender, RoutedEventArgs e) => (update.Tag as Action)?.Invoke();

    void OnPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color or UserPreferenceCategory.VisualStyle)
            app.Dispatcher.BeginInvoke(UpdateIcon);
    }

    void UpdateIcon()
    {
        var file = Desktop.TaskbarIsLight() ? "tray-light-theme.ico" : "tray-dark-theme.ico";
        var uri = new Uri($"pack://application:,,,/Assets/{file}");
        var dot = FindingWatch.NewCount > 0;
        if (AppBuild.Current.Development || dot)
            icon.Icon = Decorated(uri, AppBuild.Current.Development, dot);
        else
            icon.IconSource = BitmapFrame.Create(uri);
    }

    static readonly SolidColorBrush DevelopmentOrange = Frozen(Color.FromRgb(0xF7, 0x63, 0x0C));

    /// <summary>Windows' caution yellow, readable on a light and a dark taskbar.</summary>
    static readonly SolidColorBrush FindingDot = Frozen(Color.FromRgb(0xFC, 0xE1, 0x00));

    /// <summary>
    /// The icon with its bottom-right corner filled orange (a development build) and a dot top right
    /// (findings not yet seen): visible at 16 pixels, where text isn't.
    /// </summary>
    /// <remarks>
    /// Handed over as a System.Drawing icon: H.NotifyIcon's ImageSource conversion only takes decoded
    /// images, not a rendered bitmap. The icon file wraps one PNG image, which Windows reads since Vista.
    /// </remarks>
    static System.Drawing.Icon Decorated(Uri uri, bool corner, bool dot)
    {
        const int size = 32;
        using var stream = Application.GetResourceStream(uri)!.Stream;
        var frames = new IconBitmapDecoder(stream, BitmapCreateOptions.None, BitmapCacheOption.OnLoad).Frames;
        var frame = frames.OrderBy(f => Math.Abs(f.PixelWidth - size)).First();
        var triangle = new StreamGeometry();
        using (var g = triangle.Open())
        {
            g.BeginFigure(new Point(size, size * 0.45), isFilled: true, isClosed: true);
            g.LineTo(new Point(size, size), isStroked: false, isSmoothJoin: false);
            g.LineTo(new Point(size * 0.45, size), isStroked: false, isSmoothJoin: false);
        }
        triangle.Freeze();
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawImage(frame, new Rect(0, 0, size, size));
            if (corner)
                dc.DrawGeometry(DevelopmentOrange, null, triangle);
            if (dot)
                dc.DrawEllipse(FindingDot, new Pen(Brushes.Black, 1.5), new Point(size * 0.78, size * 0.22), size * 0.2, size * 0.2);
        }
        var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var png = new MemoryStream();
        encoder.Save(png);
        using var ico = new MemoryStream();
        using (var w = new BinaryWriter(ico, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            w.Write((short)0); w.Write((short)1); w.Write((short)1);       // ICONDIR: reserved, type icon, one image
            w.Write((byte)size); w.Write((byte)size); w.Write((byte)0); w.Write((byte)0);
            w.Write((short)1); w.Write((short)32);                          // planes, bits per pixel
            w.Write((int)png.Length); w.Write(6 + 16);                      // image size, offset after the directory
            w.Write(png.ToArray());
        }
        ico.Position = 0;
        return new System.Drawing.Icon(ico);
    }

    static SolidColorBrush Frozen(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }

    static MenuItem Item(string key, Action action)
    {
        var item = new MenuItem { Header = Text.Get(key) };
        item.Click += (_, _) => action();
        return item;
    }

    static void AutomationName(FrameworkElement element, string key) =>
        System.Windows.Automation.AutomationProperties.SetName(element, Text.Get(key));

    public void Dispose()
    {
        SystemEvents.UserPreferenceChanged -= OnPreferenceChanged;
        FindingWatch.Changed -= OnFindingsChanged;
        icon.Dispose();
    }
}
