using System.Text.Json;
using System.Text.Json.Nodes;
using Tiresias.Protocol;

namespace Tiresias.AdminTier;

public static class AdminIncidentHistory
{
    public static AdminEvents? Page(AdminReply? reply)
    {
        if (reply is not { Status: AdminStatus.Ok, Result: { } result } ||
            result["events"] is not JsonArray || result["lastId"] is not JsonValue tail || !tail.TryGetValue<long>(out var last) || last < 0 ||
            result["reviewedThrough"] is not JsonValue position || !position.TryGetValue<long>(out var reviewed) || reviewed < 0 || reviewed > last)
            return null;
        try
        {
            var page = reply.ResultAs<AdminEvents>()!;
            long previous = 0;
            foreach (var incident in page.Events)
            {
                if (incident is not { Hit.Endpoint: not null, Parents: not null } || incident.Id <= previous || incident.Id > last)
                    return null;
                previous = incident.Id;
            }
            return page;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Reads through the tail observed on the first page. A failed page cannot appear as a complete history.</summary>
    public static async Task<AdminEvents?> ReadAsync(Func<long, Task<AdminEvents?>> readPage)
    {
        long after = 0;
        long? end = null;
        var events = new List<AdminEvent>();
        while (await readPage(after) is { } page)
        {
            end ??= page.LastId;
            if (page.LastId < end)
                return null;
            foreach (var entry in page.Events)
            {
                if (entry.Id <= after)
                    return null;
                if (entry.Id > end)
                    return new(events, page.ReviewedThrough, end.Value);
                events.Add(entry);
                after = entry.Id;
            }
            if (after == end || page.Events.Count == 0)
                return new(events, page.ReviewedThrough, end.Value);
        }
        return null;
    }
}
