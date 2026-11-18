namespace Tiresias.App.Logic;

/// <summary>What the agent knows about itself, at one moment, for the tray menu and its tooltip.</summary>
/// <param name="SetUp">The first-run steps are done (or deliberately skipped).</param>
/// <param name="Enrolled">The Keyring has a broker, remote or solo; without one only user secrets are protected.</param>
/// <param name="LeaseUntil">The open lease's hard cap, when there is one.</param>
/// <param name="BrokerProblem">Solo mode: why the in-app broker isn't running.</param>
public sealed record AgentSnapshot(
    bool SetUp,
    bool Unlocked,
    bool Enrolled,
    bool Solo,
    DateTimeOffset? LeaseUntil = null,
    string? BrokerProblem = null);

/// <summary>The tray's first line, which actions are offered, and the tooltip.</summary>
public sealed record TrayView(Phrase Headline, Phrase? Mode, bool CanUnlock, bool CanLock, bool OfferSetup, Phrase Tooltip);

public static class TrayStatus
{
    public static TrayView Describe(AgentSnapshot s)
    {
        var mode = s.Solo ? new Phrase("Tray_ModeSolo") : null;
        if (!s.SetUp)
            return new(new("Tray_NotSetUp"), mode, CanUnlock: false, CanLock: false, OfferSetup: true, new("Tooltip_NotSetUp"));
        if (s.Solo && s.BrokerProblem is not null)
            return new(new("Tray_BrokerDown"), mode, CanUnlock: true, CanLock: s.Unlocked, OfferSetup: false, new("Tooltip_BrokerDown"));
        if (!s.Unlocked)
            return new(new("Tray_Locked"), mode, CanUnlock: true, CanLock: false, OfferSetup: false, new("Tooltip_Locked"));
        if (!s.Enrolled)
            return new(new("Tray_UnlockedSecretsOnly"), mode, CanUnlock: false, CanLock: true, OfferSetup: false, new("Tooltip_Unlocked"));
        return s.LeaseUntil is { } until
            ? new(new("Tray_UnlockedUntil", until.ToLocalTime()), mode, CanUnlock: false, CanLock: true, OfferSetup: false,
                new("Tooltip_UnlockedUntil", until.ToLocalTime()))
            // Unlocked, but the lease didn't open or has ended: unlocking again retries it.
            : new(new("Tray_UnlockedNoLease"), mode, CanUnlock: true, CanLock: true, OfferSetup: false, new("Tooltip_UnlockedNoLease"));
    }
}
