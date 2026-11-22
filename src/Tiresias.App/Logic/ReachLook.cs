using System.Text.Json.Serialization;

namespace Tiresias.App.Logic;

/// <summary>
/// The app's standing choice about looking inside containers (docs/containers-and-vms.md, "Consent"):
/// never asked yet, looked when asked, or daily. It widens what Tiresias reads on this PC, not what
/// leaves it, so it is a plain setting.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<ReachScan>))]
public enum ReachScan { Off, Once, Daily }

/// <summary>What a run of the checks does about the containers' contents.</summary>
public enum ReachStep
{
    /// <summary>Don't look: the checks say how to.</summary>
    Skip,
    /// <summary>Ask the engine now.</summary>
    Look,
    /// <summary>Show what the last look found, without asking again.</summary>
    Reuse,
}

public static class ReachLook
{
    static readonly TimeSpan Day = TimeSpan.FromDays(1);

    /// <param name="lookedAt">When this app last looked, or <c>null</c> since it started.</param>
    /// <param name="asked">The user pressed Check now.</param>
    public static ReachStep Decide(ReachScan setting, DateTimeOffset? lookedAt, DateTimeOffset now, bool asked) =>
        asked || (setting == ReachScan.Daily && (lookedAt is null || now - lookedAt >= Day)) ? ReachStep.Look
        : setting != ReachScan.Off && lookedAt is not null ? ReachStep.Reuse
        : ReachStep.Skip;

    /// <summary>The setting once the user has looked: <see cref="ReachScan.Daily"/> stays, anything else is <see cref="ReachScan.Once"/>.</summary>
    public static ReachScan AfterLooking(ReachScan setting) => setting == ReachScan.Daily ? ReachScan.Daily : ReachScan.Once;
}
