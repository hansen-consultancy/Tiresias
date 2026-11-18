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
/// The notification-area icon and its menu: the lock state (plus "Solo"), Unlock or Lock, and the
/// app's windows. The icon follows the taskbar's light or dark theme, and a development build's
/// icon has an orange corner and a menu line saying which build it is.
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

    public TrayController(App app)
    {
        this.app = app;
        unlock.Click += async (_, _) => await app.UnlockAsync(interactive: true);
        lockItem.Click += async (_, _) => await app.LockAsync();
        setup.Click += (_, _) => app.ShowWindow<FirstRunWindow>();
        var secrets = Item("Tray_Secrets", () => app.ShowWindow<SecretsWindow>());
        var services = Item("Tray_Services", () => app.ShowWindow<ServicesWindow>());
        var activity = Item("Tray_Activity", () => app.ShowWindow<ActivityWindow>());
        var status = Item("Tray_Status", () => app.ShowWindow<StatusWindow>());
        var about = Item("Tray_About", () => app.ShowWindow<AboutWindow>());
        var quit = Item("Tray_Quit", app.Quit);

        icon = new TaskbarIcon
        {
            ToolTipText = Text.Get("App_Name"),
            ContextMenu = new ContextMenu(),
            LeftClickCommand = new RelayCommand(app.ShowHome),
            NoLeftClickDelay = true,
        };
        if (AppBuild.Current.Development)
        {
            icon.ContextMenu.Items.Add(build);
            icon.ContextMenu.Items.Add(new Separator());
        }
        foreach (var item in new Control[] { headline, mode, unlock, lockItem, setup })
            icon.ContextMenu.Items.Add(item);
        icon.ContextMenu.Items.Add(new Separator());
        icon.ContextMenu.Items.Add(secrets);
        icon.ContextMenu.Items.Add(services);
        icon.ContextMenu.Items.Add(activity);
        icon.ContextMenu.Items.Add(status);
        icon.ContextMenu.Items.Add(about);
        icon.ContextMenu.Items.Add(updateSeparator);
        icon.ContextMenu.Items.Add(update);
        icon.ContextMenu.Items.Add(new Separator());
        icon.ContextMenu.Items.Add(quit);
        AutomationName(icon.ContextMenu, "App_Name");

        UpdateIcon();
        SystemEvents.UserPreferenceChanged += OnPreferenceChanged;
        icon.ForceCreate(enablesEfficiencyMode: false);
    }

    public void Refresh(AgentSnapshot snapshot)
    {
        var view = TrayStatus.Describe(snapshot);
        headline.Header = Text.Of(view.Headline);
        mode.Header = view.Mode is null ? null : Text.Of(view.Mode);
        mode.Visibility = view.Mode is null ? Visibility.Collapsed : Visibility.Visible;
        unlock.Visibility = view.CanUnlock ? Visibility.Visible : Visibility.Collapsed;
        lockItem.Visibility = view.CanLock ? Visibility.Visible : Visibility.Collapsed;
        setup.Visibility = view.OfferSetup ? Visibility.Visible : Visibility.Collapsed;
        icon.ToolTipText = $"{Text.Get("App_Name")} - {Text.Of(view.Tooltip)}"
            + (AppBuild.Current.Development ? $"{Environment.NewLine}{Text.Of(AppBuild.Current.Label)}" : "");
    }

    /// <summary>Offers "Update available - restart to apply" in the menu; <c>null</c> hides it.</summary>
    public void OfferUpdate(string? version, Action? apply)
    {
        var show = version is not null && apply is not null;
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
        icon.IconSource = AppBuild.Current.Development ? WithDevelopmentCorner(uri) : BitmapFrame.Create(uri);
    }

    static readonly SolidColorBrush DevelopmentOrange = Frozen(Color.FromRgb(0xF7, 0x63, 0x0C));

    /// <summary>The icon with its bottom-right corner filled orange: visible at 16 pixels, where text isn't.</summary>
    static ImageSource WithDevelopmentCorner(Uri uri)
    {
        const int size = 32;
        using var stream = Application.GetResourceStream(uri)!.Stream;
        var frames = new IconBitmapDecoder(stream, BitmapCreateOptions.None, BitmapCacheOption.OnLoad).Frames;
        var frame = frames.OrderBy(f => Math.Abs(f.PixelWidth - size)).First();
        var corner = new StreamGeometry();
        using (var g = corner.Open())
        {
            g.BeginFigure(new Point(size, size * 0.45), isFilled: true, isClosed: true);
            g.LineTo(new Point(size, size), isStroked: false, isSmoothJoin: false);
            g.LineTo(new Point(size * 0.45, size), isStroked: false, isSmoothJoin: false);
        }
        corner.Freeze();
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawImage(frame, new Rect(0, 0, size, size));
            dc.DrawGeometry(DevelopmentOrange, null, corner);
        }
        var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        bitmap.Freeze();
        return bitmap;
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
        icon.Dispose();
    }
}
