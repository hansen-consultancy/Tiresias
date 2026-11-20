namespace Tiresias.App.Logic;

/// <summary>
/// One run of an operation at a time: a caller arriving while a run is under way gets that run's
/// result (or its exception) instead of starting another. Once it has finished, the next caller
/// starts a fresh run. Used for unlocking, so requests arriving together share one Windows Hello
/// prompt instead of stacking one each.
/// </summary>
public sealed class SingleFlight<T>
{
    readonly Lock gate = new();
    Task<T>? running;

    public Task<T> RunAsync(Func<Task<T>> start)
    {
        lock (gate)
        {
            if (running is not { IsCompleted: false })
                running = Started(start);
            return running;
        }
    }

    /// <summary>A <paramref name="start"/> that throws before its first await becomes a faulted task, like any other failure.</summary>
    static async Task<T> Started(Func<Task<T>> start) => await start();
}
