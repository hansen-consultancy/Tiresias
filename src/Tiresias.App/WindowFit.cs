using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
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
/// The window takes its content's height, up to most of the work area; it opens centred on its
/// owner, or on the monitor the mouse is on (where the tray was clicked), and stays on that
/// screen as it grows. A development build says "(dev)" in
/// every title. No window sets its own Width, Height or WindowStartupLocation.
/// </summary>
public static partial class WindowFit
{
    public static readonly DependencyProperty SizeProperty = DependencyProperty.RegisterAttached(
        "Size", typeof(WindowSize), typeof(WindowFit), new PropertyMetadata(WindowSize.None, OnSizeChanged));

    public static WindowSize GetSize(Window window) => (WindowSize)window.GetValue(SizeProperty);

    public static void SetSize(Window window, WindowSize value) => window.SetValue(SizeProperty, value);

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
        if (AppBuild.Current.Development)
            window.Title = Text.Format("Window_DevTitle", window.Title);

        var hwnd = new WindowInteropHelper(window).Handle;
        var owner = window.Owner is { } o ? new WindowInteropHelper(o).Handle : 0;
        var monitor = owner != 0 ? MonitorFromWindow(owner, MonitorDefaultToNearest) : MonitorUnderMouse();
        if (Work(monitor) is not { } work)
            return;
        var scale = Scale(monitor);
        window.MaxHeight = WindowPlacement.MaxHeight(work) / scale;
        window.Width = Math.Min(window.Width, work.Width / scale);

        // The first size is the content's: centre then, before the window shows, on the owner's
        // rectangle or the monitor's work area. Content that arrives later (a list still loading)
        // grows the window downwards, and it moves up only as far as keeps it on screen. Resizing
        // by hand ends the fitting (WPF sets SizeToContent to Manual). Physical pixels throughout,
        // so a second monitor at another scale doesn't skew it.
        var placed = false;
        void Place(object? s, SizeChangedEventArgs args)
        {
            if (window.SizeToContent != SizeToContent.Height)
            {
                window.SizeChanged -= Place;
                return;
            }
            if (!GetWindowRect(hwnd, out var self))
                return;
            var on = !placed ? owner != 0 && GetWindowRect(owner, out var ownerRect) ? ownerRect.Box : work : (ScreenBox?)null;
            var (left, top) = on is { } box
                ? WindowPlacement.Centre(box, self.Box.Width, self.Box.Height, work)
                : WindowPlacement.Inside(self.Box, work);
            placed = true;
            SetWindowPos(hwnd, 0, (int)left, (int)top, 0, 0, NoSize | NoZOrder | NoActivate);
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
