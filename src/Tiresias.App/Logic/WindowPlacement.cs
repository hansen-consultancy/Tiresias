namespace Tiresias.App.Logic;

/// <summary>A rectangle on screen, in whatever unit the caller measures in.</summary>
public readonly record struct ScreenBox(double Left, double Top, double Width, double Height)
{
    public double Right => Left + Width;

    public double Bottom => Top + Height;
}

/// <summary>
/// Where every window opens (docs/app-design.md, rule 1): as tall as its content but no taller
/// than most of the work area, centred on what it centres on (its owner, or the monitor), and
/// never past the work area's edges.
/// </summary>
public static class WindowPlacement
{
    /// <summary>The share of the work area's height a window may take before its body scrolls.</summary>
    public const double HeightShare = 0.85;

    public static double MaxHeight(ScreenBox workArea) => Math.Floor(workArea.Height * HeightShare);

    /// <summary>The top-left corner that centres a window of this size on <paramref name="on"/>, kept inside <paramref name="workArea"/>.</summary>
    public static (double Left, double Top) Centre(ScreenBox on, double width, double height, ScreenBox workArea) =>
        (Clamp(on.Left + (on.Width - width) / 2, workArea.Left, workArea.Right - width),
         Clamp(on.Top + (on.Height - height) / 2, workArea.Top, workArea.Bottom - height));

    /// <summary>Where a window that grew goes: where it is, moved up or left only as far as keeps it in <paramref name="workArea"/>.</summary>
    public static (double Left, double Top) Inside(ScreenBox window, ScreenBox workArea) =>
        (Clamp(window.Left, workArea.Left, workArea.Right - window.Width),
         Clamp(window.Top, workArea.Top, workArea.Bottom - window.Height));

    /// <summary>A window larger than the work area keeps its top-left corner in it.</summary>
    static double Clamp(double value, double min, double max) => Math.Round(Math.Max(min, Math.Min(value, max)));
}
