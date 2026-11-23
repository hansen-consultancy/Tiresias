using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App;

/// <summary>
/// The last look inside the containers, kept for this app's lifetime so Home and the background
/// checks show its findings between looks. Names only, as <see cref="ReachContents"/> holds them.
/// </summary>
static class ReachMemory
{
    sealed record Look(ReachContents Contents, DateTimeOffset At);

    static volatile Look? last;

    public static DateTimeOffset? LookedAt => last?.At;

    /// <summary>The contents for this run of the checks, per <see cref="ReachLook.Decide"/>; <c>null</c> when it doesn't look.</summary>
    public static async Task<ReachContents?> ForRunAsync(MachineProbe probe, bool asked)
    {
        var settings = AppSettings.Load();
        var now = DateTimeOffset.UtcNow;
        switch (ReachLook.Decide(settings.ReachScan, last?.At, now, asked))
        {
            case ReachStep.Look:
                var contents = await probe.ReachContentsAsync(ReachScope.Docker, CancellationToken.None);
                if (!ReachLook.Counts(contents))
                    return contents;
                last = new(contents, now);
                if (ReachLook.AfterLooking(settings.ReachScan) is var after && after != settings.ReachScan)
                    (settings with { ReachScan = after }).Save();
                return contents;
            case ReachStep.Reuse:
                return last?.Contents;
            default:
                return null;
        }
    }
}
