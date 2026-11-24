using System.Globalization;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Tiresias.Alerts;
using Tiresias.Protocol;

namespace Tiresias.App;

/// <summary>
/// Draws an LcdHub alert frame (docs/alerts.md, <i>LcdHub alert frame</i>) with WPF: the card's lines,
/// left-aligned and shrunk to fit, on red for <c>critical</c>. Runs on the app's UI thread, as WPF drawing must.
/// </summary>
internal static class LcdHubCardRenderer
{
    static readonly Typeface Bold = new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal);
    static readonly Typeface Semibold = new(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);

    public static uint[] Render(LcdHubCard card, int width, int height) =>
        // Null once the app is shutting down: the link then draws nothing.
        Application.Current?.Dispatcher.Invoke(() => Draw(card, width, height)) ?? [];

    static uint[] Draw(LcdHubCard card, int width, int height)
    {
        var critical = card.Severity == AlertSeverity.Critical;
        var background = critical ? Color.FromRgb(0x7F, 0x1D, 0x1D) : Color.FromRgb(0x14, 0x14, 0x14);
        var accent = critical ? Color.FromRgb(0xF8, 0x71, 0x71) : Color.FromRgb(0x3B, 0x82, 0xF6);
        var text = new SolidColorBrush(Color.FromRgb(0xF5, 0xF5, 0xF5));
        double[] sizes = [0.15, 0.26, 0.12];
        var margin = width * 0.05;

        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.DrawRectangle(new SolidColorBrush(background), null, new Rect(0, 0, width, height));
            dc.DrawRectangle(new SolidColorBrush(accent), null, new Rect(0, 0, Math.Max(8, width * 0.012), height));
            var lines = card.Lines.Select((line, i) => Fit(line, height * sizes[Math.Min(i, sizes.Length - 1)], i == 1 ? Semibold : Bold,
                i == 0 ? new SolidColorBrush(accent) : text, width - 2 * margin)).ToList();
            var gap = height * 0.04;
            var y = (height - lines.Sum(l => l.Height) - gap * (lines.Count - 1)) / 2;
            foreach (var line in lines)
            {
                dc.DrawText(line, new Point(margin, y));
                y += line.Height + gap;
            }
        }

        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        // Pbgra32 on an opaque background is B, G, R, 255 per pixel: the BGRX LcdHub takes.
        var pixels = new uint[width * height];
        bitmap.CopyPixels(pixels, width * 4, 0);
        return pixels;
    }

    static FormattedText Fit(string line, double size, Typeface face, Brush brush, double maxWidth)
    {
        var text = Make(line, size, face, brush);
        return text.Width <= maxWidth ? text : Make(line, Math.Max(8, size * maxWidth / text.Width), face, brush);
    }

    static FormattedText Make(string line, double size, Typeface face, Brush brush) =>
        new(line, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, face, size, brush, 1.0);
}
