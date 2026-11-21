namespace Tiresias.Alerts;

/// <summary>A sink that hasn't delivered since <see cref="Since"/>; <see cref="Stopped"/> once a receiver refused its definition.</summary>
public sealed record SinkFailure(DateTimeOffset Since, bool Stopped);

/// <summary>A sink whose alerts aren't arriving, as Home's finding and <c>alerts.failing</c> name it. Never its address or credential.</summary>
public sealed record FailingSink(string Id, bool Stopped);

/// <summary>
/// When a sink counts as failing (docs/alerts.md, <i>Delivery</i>): it stopped (a non-429/503 4xx or a
/// redirect), or nothing has gone through for 15 minutes. A delivery clears it. Pure.
/// </summary>
public static class SinkHealth
{
    public static readonly TimeSpan FailingAfter = TimeSpan.FromMinutes(15);

    /// <summary>The failure after one attempt's <paramref name="status"/>: kept from the first failed attempt until one gets through.</summary>
    public static SinkFailure? After(SinkFailure? failure, DeliveryStatus status, DateTimeOffset now) => status switch
    {
        DeliveryStatus.Delivered => null,
        DeliveryStatus.Stop => new(failure?.Since ?? now, true),
        _ => failure ?? new(now, false),
    };

    public static bool IsFailing(SinkFailure? failure, DateTimeOffset now) =>
        failure is { } f && (f.Stopped || now - f.Since >= FailingAfter);

    /// <summary>The sinks that became failing between <paramref name="before"/> and <paramref name="now"/>: each gets one <c>alerts.failing</c>.</summary>
    public static IReadOnlyList<FailingSink> NewlyFailing(IReadOnlyList<FailingSink> before, IReadOnlyList<FailingSink> now) =>
        [.. now.Where(f => !before.Any(b => b.Id == f.Id))];
}
