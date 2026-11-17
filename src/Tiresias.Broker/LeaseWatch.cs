namespace Tiresias.Broker;

/// <summary>
/// Ends a lease that ran out even when no request arrives to notice, so its DEKs don't sit in RAM
/// past the hard cap or a lost heartbeat for longer than one period.
/// </summary>
sealed class LeaseWatch(BrokerState state, TimeProvider time) : BackgroundService
{
    static readonly TimeSpan Period = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Period, time);
        while (await timer.WaitForNextTickAsync(stoppingToken))
            state.Tick();
    }
}
