using System.Text.Json.Nodes;
using Tiresias.AdminTier;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>Reads the signed-in user's service history. Only an explicit elevated review advances the shared reminder position.</summary>
public static class AdminIncidents
{
    public static async Task<AdminEvents?> WaitAsync(long after, CancellationToken ct)
    {
        if (DemoMode.On)
            return null;
        var args = new JsonObject { ["after"] = after, ["wait"] = AdminWire.MaxWaitSeconds };
        var reply = await AdminClient.SendAsync(AdminOps.EventsWait, args, TimeSpan.FromSeconds(AdminWire.MaxWaitSeconds + 10), ct);
        return AdminIncidentHistory.Page(reply);
    }

    public static AdminSetupResult Review(long through)
    {
        var reply = Task.Run(() => AdminClient.SendAsync(AdminOps.EventsReview, new() { ["through"] = through })).GetAwaiter().GetResult();
        return AdminIncidentHistory.Page(reply) is { } result && result.ReviewedThrough >= through ? AdminSetupResult.Done : AdminSetupResult.Failed;
    }

    public static AdminEvents? History() => Task.Run(HistoryAsync).GetAwaiter().GetResult();

    public static async Task<AdminEvents?> HistoryAsync()
    {
        var installed = AdminClient.ServiceInstalled();
        if (installed != true)
            return installed == false ? new([], 0, 0) : null;
        return await AdminIncidentHistory.ReadAsync(async after =>
        {
            var reply = await AdminClient.SendAsync(AdminOps.EventsHistory, new() { ["after"] = after });
            return AdminIncidentHistory.Page(reply);
        });
    }
}
