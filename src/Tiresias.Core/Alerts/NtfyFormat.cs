using System.Net.Http.Headers;
using System.Text;
using Tiresias.Protocol;

namespace Tiresias.Alerts;

/// <summary>
/// An alert as an ntfy message (docs/alerts.md, <i>Sinks</i>): a <c>POST</c> to the topic URL with the
/// title in <c>Title</c>, the severity as <c>Priority</c> and <c>Tags</c>, and a one-line plain-text
/// body. Built from the redacted payload only; a trusted sink adds the program's file name, never its
/// folder, which can name the user.
/// </summary>
public static class NtfyFormat
{
    /// <summary>ntfy's priority: 2 (low) to 5 (urgent). 1 (min) is never used, so an alert always shows.</summary>
    public static int Priority(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => 5,
        AlertSeverity.High => 4,
        AlertSeverity.Warning => 3,
        _ => 2,
    };

    /// <summary>ntfy shows a tag that names an emoji as that emoji, ahead of the title.</summary>
    public static string Tags(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => "rotating_light",
        AlertSeverity.High => "warning",
        AlertSeverity.Warning => "large_orange_diamond",
        _ => "information_source",
    };

    /// <summary>"Critical on desk, ×1. Open Tiresias.", with the program's file name on a trusted sink.</summary>
    public static string Body(AlertPayload payload)
    {
        var severity = payload.Severity.ToString();
        var program = FileName(payload.Detail?.Program) is { Length: > 0 } name ? $" ({name})" : "";
        return $"{severity} on {payload.Machine}, ×{payload.Count}{program}. Open Tiresias.";
    }

    public static HttpRequestMessage Request(AlertPayload payload, NtfySink sink)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, sink.Topic) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Body(payload))) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain") { CharSet = "utf-8" };
        // The title comes from the event table, so it is ASCII and fits a header as is.
        request.Headers.TryAddWithoutValidation("Title", payload.Title);
        request.Headers.TryAddWithoutValidation("Priority", Priority(payload.Severity).ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation("Tags", Tags(payload.Severity));
        if (sink.Token is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sink.Token);
        return request;
    }

    /// <summary>The last segment of a Windows or POSIX path, on any OS.</summary>
    static string? FileName(string? path) => path?[(path.LastIndexOfAny(['\\', '/']) + 1)..];
}
