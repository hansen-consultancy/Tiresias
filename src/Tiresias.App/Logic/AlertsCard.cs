using Tiresias.Alerts;
using Tiresias.Protocol;

namespace Tiresias.App.Logic;

/// <summary>One sink as the Alerts card lists it.</summary>
public sealed record AlertSinkRow(string Id, Phrase Detail, bool Muted);

/// <summary>What the Alerts card in About says (docs/alerts.md), and what the add-a-webhook, add-ntfy and add-LcdHub forms accept.</summary>
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
        { Error: AlertCenter.NoHub } => new("Alerts_TestNoHub", sinkId),
        _ => new("Alerts_TestUnreachable", sinkId, result.Error),
    };

    /// <summary>
    /// The webhook form's fields as a sink, or the first problem with them. <paramref name="machine"/> is
    /// asked only for the first sink (<paramref name="needsMachine"/>) and is required then: never the host name.
    /// </summary>
    public static (WebhookSink? Sink, Phrase? Problem) Build(bool needsMachine, string machine, string id, string url,
        string headerName, string headerValue, AlertSeverity threshold, bool trusted, IEnumerable<string> existingIds)
    {
        if (CheckCommon(needsMachine, machine, ref id, existingIds) is { } common)
            return (null, common);
        if (SinkRules.CheckUrl(url, out var parsed) is var urlProblem and not SinkProblem.None)
            return (null, UrlProblem(urlProblem));
        headerName = headerName.Trim();
        KeyValuePair<string, string>[] headers = headerName.Length == 0 && headerValue.Length == 0 ? [] : [KeyValuePair.Create(headerName, headerValue)];
        foreach (var (name, value) in headers)
        {
            switch (SinkRules.CheckHeader(name, value))
            {
                case SinkProblem.HeaderName:
                    return (null, new("Alerts_HeaderName"));
                case SinkProblem.HeaderReserved:
                    return (null, new("Alerts_HeaderReserved", name));
                case SinkProblem.HeaderValue:
                    return (null, new("Alerts_HeaderValue"));
            }
        }
        return (new WebhookSink(id, parsed!, headers, threshold, Redaction(trusted)), null);
    }

    /// <summary>The ntfy form's fields as a sink, or the first problem with them. An empty token is an open topic.</summary>
    public static (NtfySink? Sink, Phrase? Problem) BuildNtfy(bool needsMachine, string machine, string id, string server, string topic,
        string token, AlertSeverity threshold, bool trusted, IEnumerable<string> existingIds)
    {
        if (CheckCommon(needsMachine, machine, ref id, existingIds) is { } common)
            return (null, common);
        if (SinkRules.CheckNtfy(server, topic, out var url) is var problem and not SinkProblem.None)
            return (null, problem == SinkProblem.Topic ? new("Alerts_NtfyTopicBad") : UrlProblem(problem));
        token = token.Trim();
        if (token.Length > 0 && SinkRules.CheckToken(token) != SinkProblem.None)
            return (null, new("Alerts_NtfyTokenBad"));
        return (new NtfySink(id, url!, token.Length > 0 ? token : null, threshold, Redaction(trusted)), null);
    }

    /// <summary>
    /// The LcdHub form's fields as a sink, or the first problem with them. There is no address, no
    /// credential and no trusted choice: the screen shows the title and count only, so it is always public.
    /// </summary>
    public static (LcdHubSink? Sink, Phrase? Problem) BuildLcdHub(bool needsMachine, string machine, string id, AlertSeverity threshold,
        IEnumerable<AlertSink> existing)
    {
        var sinks = existing.ToList();
        if (HasLcdHub(sinks))
            return (null, new("Alerts_LcdHubTaken"));
        if (CheckCommon(needsMachine, machine, ref id, sinks.Select(s => s.Id)) is { } common)
            return (null, common);
        return (new LcdHubSink(id, threshold), null);
    }

    /// <summary>A machine has one LcdHub, so it takes one LcdHub sink; the card offers to add one only while there is none.</summary>
    public static bool HasLcdHub(IEnumerable<AlertSink>? sinks) => sinks?.Any(s => s is LcdHubSink) == true;

    static Phrase? CheckCommon(bool needsMachine, string machine, ref string id, IEnumerable<string> existingIds)
    {
        if (needsMachine && string.IsNullOrWhiteSpace(machine))
            return new("Alerts_NeedMachine");
        id = id.Trim();
        if (SinkRules.CheckId(id) != SinkProblem.None)
            return new("Alerts_BadId");
        return existingIds.Contains(id, StringComparer.Ordinal) ? new("Alerts_IdTaken", id) : null;
    }

    static Phrase UrlProblem(SinkProblem problem) => problem == SinkProblem.UserInfo ? new("Alerts_UrlUserInfo") : new("Alerts_UrlNotHttps");

    static AlertRedaction Redaction(bool trusted) => trusted ? AlertRedaction.Trusted : AlertRedaction.Public;

    static Phrase Severity(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => new("Alerts_Critical"),
        AlertSeverity.High => new("Alerts_High"),
        AlertSeverity.Warning => new("Alerts_Warning"),
        _ => new("Alerts_Info"),
    };
}
