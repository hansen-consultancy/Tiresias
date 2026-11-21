namespace Tiresias.App.Logic;

/// <summary>
/// Which windows stay out of screenshots, recordings and screen sharing. All of them do, except
/// that a debug build started with <see cref="Variable"/> set to <c>1</c> lets a window be shared
/// while it shows no values, so it can be demonstrated while it is developed. The debug build
/// serves the real vault, so a page or dialog that shows values stays excluded even then. Only a
/// debug build reads the variable (<c>Desktop.CaptureAllowed</c>); a release build has no way to allow capture.
/// </summary>
public static class CaptureRule
{
    public const string Variable = "TIRESIAS_ALLOW_CAPTURE";

    /// <summary>Whether the variable's value, read at start, asks for capture: exactly <c>1</c>.</summary>
    public static bool Allowed(string? variable) => variable == "1";

    /// <summary>Whether a window is excluded now: always, unless capture is allowed and it shows no values.</summary>
    public static bool Excluded(bool captureAllowed, bool showsValues) => !captureAllowed || showsValues;
}
