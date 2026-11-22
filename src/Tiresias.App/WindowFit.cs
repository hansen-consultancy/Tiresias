using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Tiresias.Agent;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>The three widths a window comes in (docs/app-design.md, rule 1).</summary>
public enum WindowSize
{
    /// <summary>Not fitted: the window sizes and places itself.</summary>
    None,

    /// <summary>480: prompts and questions.</summary>
    Narrow,

    /// <summary>720: windows of cards and forms.</summary>
    Standard,

    /// <summary>960: windows built around a grid.</summary>
    Wide,
}

/// <summary>
/// One placement and size rule for every window, set in XAML as <c>l:WindowFit.Size="Standard"</c>.
/// A window opens at its final size, centred on its owner or the window it was opened from, or on
/// the monitor the mouse is on (where the tray was clicked), and keeps that size: content that arrives later scrolls in the window's
/// one scroll region rather than growing it. Its height is its content's, up to most of the work
/// area; a window whose list loads after it opens says <c>l:WindowFit.Tall="True"</c> and opens at a
/// fixed share of the work area instead, since its content's height is not known yet. A
/// development build says "(dev)" in every title, and demo mode "(demo)". No window sets its own Width, Height or
/// WindowStartupLocation.
/// </summary>
public static partial class WindowFit
{
    public static readonly DependencyProperty SizeProperty = DependencyProperty.RegisterAttached(
        "Size", typeof(WindowSize), typeof(WindowFit), new PropertyMetadata(WindowSize.None, OnSizeChanged));

    public static WindowSize GetSize(Window window) => (WindowSize)window.GetValue(SizeProperty);

    public static void SetSize(Window window, WindowSize value) => window.SetValue(SizeProperty, value);

    public static readonly DependencyProperty TallProperty = DependencyProperty.RegisterAttached(
        "Tall", typeof(bool), typeof(WindowFit), new PropertyMetadata(false));

    public static bool GetTall(Window window) => (bool)window.GetValue(TallProperty);

    public static void SetTall(Window window, bool value) => window.SetValue(TallProperty, value);

    const double MinWidth = 420;
    const double MinHeight = 240;

    static void OnSizeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not Window window || DesignerProperties.GetIsInDesignMode(window) || e.NewValue is not WindowSize size || size == WindowSize.None)
            return;
        window.Width = size switch
        {
            WindowSize.Narrow => 480,
            WindowSize.Wide => 960,
            _ => 720,
        };
        window.MinWidth = Math.Min(MinWidth, window.Width);
        window.MinHeight = MinHeight;
        window.SizeToContent = SizeToContent.Height;
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.SourceInitialized += OnSourceInitialized;
    }

    static void OnSourceInitialized(object? sender, EventArgs e)
    {
        var window = (Window)sender!;
        window.SourceInitialized -= OnSourceInitialized;
        if (DemoMode.On)
            window.Title = Text.Format("Window_DemoTitle", window.Title);
        // The standalone CLI shares this window without starting the desktop updater.
        else if (Application.Current is App && AppBuild.Current.Development)
            window.Title = Text.Format("Window_DevTitle", window.Title);

        var hwnd = new WindowInteropHelper(window).Handle;
        // A window opened from another (Home's buttons open peers, not owned windows) centres on
        // the one that was active when it opened; from the tray none is, and the mouse decides.
        var opener = window.Owner ?? Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w != window && w.IsActive);
        var owner = opener is not null ? new WindowInteropHelper(opener).Handle : 0;
        var monitor = owner != 0 ? MonitorFromWindow(owner, MonitorDefaultToNearest) : MonitorUnderMouse();
        if (Work(monitor) is not { } work)
            return;
        var scale = Scale(monitor);
        var on = owner != 0 && GetWindowRect(owner, out var ownerRect) ? ownerRect.Box : work;
        window.MaxHeight = WindowPlacement.MaxHeight(work) / scale;
        window.Width = Math.Min(window.Width, work.Width / scale);

        // Physical pixels throughout, so a second monitor at another scale doesn't skew it. The
        // size comes from WPF, not GetWindowRect: when the first layout reports it, the native
        // window may not have taken it yet.
        void MoveTo(double width, double height)
        {
            var (left, top) = WindowPlacement.Centre(on, width * scale, height * scale, work);
            SetWindowPos(hwnd, 0, (int)left, (int)top, 0, 0, NoSize | NoZOrder | NoActivate);
        }

        if (GetTall(window))
        {
            window.SizeToContent = SizeToContent.Manual;
            window.Height = WindowPlacement.TallHeight(work) / scale;
            MoveTo(window.Width, window.Height);
            return;
        }

        // The content's height, measured now: WPF lays the window out only after showing it, at
        // Windows' default place, so waiting for that layout would show it there first. The
        // layout then only fixes the size; content that arrives later scrolls.
        window.Measure(new Size(window.Width, window.MaxHeight));
        var height = Math.Min(window.DesiredSize.Height, window.MaxHeight);
        MoveTo(window.Width, height);
        void Place(object? s, SizeChangedEventArgs args)
        {
            window.SizeChanged -= Place;
            window.SizeToContent = SizeToContent.Manual;
            if (Math.Abs(args.NewSize.Height - height) >= 1)
                MoveTo(args.NewSize.Width, args.NewSize.Height);
        }
        window.SizeChanged += Place;
    }

    static nint MonitorUnderMouse() =>
        MonitorFromPoint(GetCursorPos(out var point) ? point : default, MonitorDefaultToNearest);

    static ScreenBox? Work(nint monitor)
    {
        var info = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
        return monitor != 0 && GetMonitorInfo(monitor, ref info) ? info.Work.Box : null;
    }

    /// <summary>Physical pixels per device-independent one on that monitor.</summary>
    static double Scale(nint monitor) =>
        GetDpiForMonitor(monitor, 0, out var dpi, out _) == 0 && dpi > 0 ? dpi / 96.0 : 1.0;

    const uint MonitorDefaultToNearest = 2;
    const uint NoSize = 0x0001;
    const uint NoZOrder = 0x0004;
    const uint NoActivate = 0x0010;

    [StructLayout(LayoutKind.Sequential)]
    struct Point
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;

        public readonly ScreenBox Box => new(Left, Top, Right - Left, Bottom - Top);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MonitorInfo
    {
        public int Size;
        public Rect Monitor;
        public Rect Work;
        public uint Flags;
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out Point point);

    [LibraryImport("user32.dll")]
    private static partial nint MonitorFromPoint(Point point, uint flags);

    [LibraryImport("user32.dll")]
    private static partial nint MonitorFromWindow(nint hwnd, uint flags);

    [LibraryImport("user32.dll", EntryPoint = "GetMonitorInfoW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetMonitorInfo(nint monitor, ref MonitorInfo info);

    [LibraryImport("shcore.dll")]
    private static partial int GetDpiForMonitor(nint monitor, int type, out uint dpiX, out uint dpiY);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetWindowRect(nint hwnd, out Rect rect);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowPos(nint hwnd, nint after, int x, int y, int width, int height, uint flags);
}
