using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class SingleFlightTests
{
    [Test]
    public async Task Callers_arriving_while_an_unlock_runs_share_it()
    {
        var flight = new SingleFlight<string>();
        var prompt = new TaskCompletionSource<string>();
        var starts = 0;
        Task<string> Unlock()
        {
            starts++;
            return prompt.Task;
        }

        var first = flight.RunAsync(Unlock);
        var second = flight.RunAsync(Unlock);
        prompt.SetResult("unlocked");

        Assert.That(starts, Is.EqualTo(1));
        Assert.That(await first, Is.EqualTo("unlocked"));
        Assert.That(await second, Is.EqualTo("unlocked"));
    }

    [Test]
    public async Task A_caller_after_the_run_finished_starts_a_new_one()
    {
        var flight = new SingleFlight<int>();
        var starts = 0;

        await flight.RunAsync(() => Task.FromResult(++starts));
        var again = await flight.RunAsync(() => Task.FromResult(++starts));

        Assert.That(again, Is.EqualTo(2));
    }

    [Test]
    public async Task Every_waiting_caller_sees_the_failure_and_the_next_caller_tries_again()
    {
        var flight = new SingleFlight<int>();
        var prompt = new TaskCompletionSource<int>();

        var first = flight.RunAsync(() => prompt.Task);
        var second = flight.RunAsync(() => Task.FromResult(99));
        prompt.SetException(new InvalidOperationException("The Windows Hello prompt expired before it was answered."));

        Assert.ThrowsAsync<InvalidOperationException>(() => first);
        Assert.ThrowsAsync<InvalidOperationException>(() => second);
        Assert.That(await flight.RunAsync(() => Task.FromResult(1)), Is.EqualTo(1));
    }

    [Test]
    public void A_start_that_throws_at_once_fails_its_task_and_leaves_no_run_behind()
    {
        var flight = new SingleFlight<int>();

        var failed = flight.RunAsync(() => throw new InvalidOperationException("Windows Hello is not set up on this machine."));

        Assert.That(failed.IsFaulted, Is.True);
        Assert.That(flight.RunAsync(() => Task.FromResult(1)).Result, Is.EqualTo(1));
    }
}
