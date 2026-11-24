using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>
/// The card that says why a Windows Hello or UAC prompt is about to show (docs/app-design.md,
/// rule 13). Windows puts none of our words in those prompts, so this is where the reason goes. It
/// never takes focus or a click: the prompt that follows must get the keyboard, and a card that could
/// be answered would look like the prompt itself.
/// </summary>
public partial class PromptCardWindow : Window
{
    PromptCardWindow(PromptCardView view)
    {
        InitializeComponent();
        Heading.Text = Text.Of(view.Heading);
        Reason.Text = Text.Of(view.Reason);
        SourceInitialized += (_, _) =>
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            SetWindowLongPtrW(hwnd, GwlExStyle, GetWindowLongPtrW(hwnd, GwlExStyle) | WsExNoActivate | WsExToolWindow);
            var round = DwmcpRound;
            _ = DwmSetWindowAttribute(hwnd, DwmwaWindowCornerPreference, ref round, sizeof(int));
        };
        // Above the middle of the screen, where Windows centres both prompts, so the card sits just over them.
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Left + (area.Width - ActualWidth) / 2;
            Top = Math.Max(area.Top + 16, area.Top + area.Height / 2 - PromptHalfHeight - ActualHeight);
        };
    }

    /// <summary>Roughly half of the Hello prompt's height, which is what the card keeps clear of below it.</summary>
    const double PromptHalfHeight = 250;

    /// <summary>
    /// Shows the card for <paramref name="why"/> and returns once it is on screen, so it is there
    /// before the prompt; disposing the result closes it. Callable from any thread. Outside the app
    /// (no <see cref="Application"/>: uninstalling, <c>tir</c>) it shows nothing.
    /// </summary>
    public static IDisposable Show(PromptReason why, PromptKind kind)
    {
        if (Application.Current?.Dispatcher is not { } dispatcher || dispatcher.HasShutdownStarted)
            return Nothing.Instance;
        var view = PromptWhy.Describe(why, kind);
        if (dispatcher.CheckAccess())
        {
            var here = new PromptCardWindow(view);
            here.Show();
            // The caller is about to block this thread on the prompt: draw the card first.
            dispatcher.Invoke(static () => { }, DispatcherPriority.ContextIdle);
            return new Closer(dispatcher, here);
        }
        using var drawn = new ManualResetEventSlim();
        var card = dispatcher.Invoke(() =>
        {
            var opened = new PromptCardWindow(view);
            opened.ContentRendered += (_, _) => drawn.Set();
            opened.Show();
            return opened;
        });
        // A busy UI thread must not hold the prompt back for long; the card then shows a moment late.
        drawn.Wait(TimeSpan.FromSeconds(1));
        return new Closer(dispatcher, card);
    }

    sealed class Closer(Dispatcher dispatcher, Window card) : IDisposable
    {
        int closed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref closed, 1) == 0)
                dispatcher.BeginInvoke(card.Close);
        }
    }

    sealed class Nothing : IDisposable
    {
        public static readonly Nothing Instance = new();

        public void Dispose()
        {
        }
    }

    const int GwlExStyle = -20;
    const nint WsExNoActivate = 0x08000000;
    const nint WsExToolWindow = 0x00000080;
    const int DwmwaWindowCornerPreference = 33;
    const int DwmcpRound = 2;

    [LibraryImport("user32.dll")]
    private static partial nint GetWindowLongPtrW(nint hwnd, int index);

    [LibraryImport("user32.dll")]
    private static partial nint SetWindowLongPtrW(nint hwnd, int index, nint value);

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(nint hwnd, int attribute, ref int value, int size);
}
