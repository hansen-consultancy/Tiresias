using Tiresias.Alerts;
using Tiresias.Protocol;

namespace Tiresias.App.Logic;

/// <summary>One sink as the Alerts card lists it.</summary>
public sealed record AlertSinkRow(string Id, Phrase Detail, bool Muted);

/// <summary>What the Alerts card in About says (docs/alerts.md, phase 2), and what the add-a-webhook form accepts.</summary>
public static class AlertsCard
{
    /// <param name="opened">Whether <c>alerts.json</c> has been opened since the app started (it opens at unlock).</param>
    public static Phrase Describe(bool opened, AlertsConfig? config) =>
        !opened ? new("Alerts_Locked")
        : config is null || config.Sinks.Count == 0 ? new("Alerts_None")
        : new("Alerts_Summary", config.Machine);

    public static IReadOnlyList<AlertSinkRow> Rows(AlertsConfig? config, IReadOnlyDictionary<string, SinkNarrowing>? narrowing, Func<string, bool> stopped) =>
        config is null ? [] : [.. config.Live(narrowing).Select(sink =>
        {
            var muted = narrowing?.GetValueOrDefault(sink.Id)?.Muted == true;
            var detail = muted ? new Phrase("Alerts_RowMuted", Severity(sink.Threshold))
                : stopped(sink.Id) ? new Phrase("Alerts_RowStopped", Severity(sink.Threshold))
                : sink.Redaction == AlertRedaction.Trusted ? new Phrase("Alerts_RowTrusted", Severity(sink.Threshold))
                : new Phrase("Alerts_RowPublic", Severity(sink.Threshold));
            return new AlertSinkRow(sink.Id, detail, muted);
        })];

    /// <summary>How <b>Send a test alert</b> went: the status code or the exception's type, never more.</summary>
    public static Phrase Outcome(string sinkId, DeliveryResult? result) => result switch
    {
        null => new("Alerts_TestGone", sinkId),
        { Status: DeliveryStatus.Delivered } => new("Alerts_TestDelivered", sinkId),
        { StatusCode: { } code } => new("Alerts_TestRefused", sinkId, code),
        { Error: "Timeout" } => new("Alerts_TestTimeout", sinkId),
        _ => new("Alerts_TestUnreachable", sinkId, result.Error),
    };

    /// <summary>
    /// The form's fields as a sink, or the first problem with them. <paramref name="machine"/> is asked
    /// only for the first sink (<paramref name="needsMachine"/>) and is required then: never the host name.
    /// </summary>
    public static (WebhookSink? Sink, Phrase? Problem) Build(bool needsMachine, string machine, string id, string url,
        string headerName, string headerValue, AlertSeverity threshold, bool trusted, IEnumerable<string> existingIds)
    {
        if (needsMachine && string.IsNullOrWhiteSpace(machine))
            return (null, new("Alerts_NeedMachine"));
        id = id.Trim();
        if (WebhookRules.CheckId(id) != WebhookProblem.None)
            return (null, new("Alerts_BadId"));
        if (existingIds.Contains(id, StringComparer.Ordinal))
            return (null, new("Alerts_IdTaken", id));
        if (WebhookRules.CheckUrl(url, out var parsed) is var urlProblem and not WebhookProblem.None)
            return (null, urlProblem == WebhookProblem.UserInfo ? new("Alerts_UrlUserInfo") : new("Alerts_UrlNotHttps"));
        headerName = headerName.Trim();
        KeyValuePair<string, string>[] headers = headerName.Length == 0 && headerValue.Length == 0 ? [] : [KeyValuePair.Create(headerName, headerValue)];
        foreach (var (name, value) in headers)
        {
            switch (WebhookRules.CheckHeader(name, value))
            {
                case WebhookProblem.HeaderName:
                    return (null, new("Alerts_HeaderName"));
                case WebhookProblem.HeaderReserved:
                    return (null, new("Alerts_HeaderReserved", name));
                case WebhookProblem.HeaderValue:
                    return (null, new("Alerts_HeaderValue"));
            }
        }
        return (new WebhookSink(id, parsed!, headers, threshold, trusted ? AlertRedaction.Trusted : AlertRedaction.Public), null);
    }

    static Phrase Severity(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => new("Alerts_Critical"),
        AlertSeverity.High => new("Alerts_High"),
        AlertSeverity.Warning => new("Alerts_Warning"),
        _ => new("Alerts_Info"),
    };
}
