namespace Tiresias.Agent;

/// <summary>
/// Says why a Windows Hello prompt shows. Windows takes no text of ours for the prompt
/// (<c>RequestSignAsync</c> has no message), so a host that can show something of its own, the app,
/// sets <see cref="Announce"/>; <see cref="HelloKeyWrapper"/> calls it just before each prompt and
/// disposes what it returns once the prompt is answered. The reason is ambient: a caller wraps the
/// work that may prompt in <see cref="Because"/>, and it flows through awaits and <c>Task.Run</c> to
/// whichever call ends up prompting, so no signature between the two has to carry it.
/// </summary>
public static class HelloPrompts
{
    static readonly AsyncLocal<object?> reason = new();

    /// <summary>
    /// Shows the reason (whatever was passed to <see cref="Because"/>, or <c>null</c> when nobody named
    /// one) before a prompt; called on the thread about to block on it. <c>null</c> in <c>tir</c>.
    /// </summary>
    public static Func<object?, IDisposable>? Announce { get; set; }

    /// <summary>Names the reason for any Hello prompt the work started inside this scope shows.</summary>
    public static IDisposable Because(object why)
    {
        var outer = reason.Value;
        reason.Value = why;
        return new Restore(outer);
    }

    /// <summary>The host's card for the prompt about to show, or nothing.</summary>
    internal static IDisposable? Showing() => Announce?.Invoke(reason.Value);

    sealed class Restore(object? outer) : IDisposable
    {
        public void Dispose() => reason.Value = outer;
    }
}
