using System.Text.Json.Nodes;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.AdminTier;

public static class AdminBlockCheck
{
    /// <summary>The service considers every possible hash match when asked without a digest. Hash the image only if such history exists.</summary>
    public static async Task<ReleasePolicy> ReadAsync(bool? installed, string? image, Func<string?, Task<AdminReply?>> query, Func<string, string?> hash)
    {
        if (installed == false)
            return new(new(-1));
        if (installed is null)
            return new(default, ReleasePolicy.Unavailable);
        var status = Read(await query(null));
        if (status is { Generation: > 0 } && image is not null && hash(image) is { } digest)
            status = Read(await query(digest));
        return status is null ? new(default, ReleasePolicy.Unavailable)
            : new(new(status.Generation), status.Blocked ? $"The admin tier blocked access for {image ?? "an unidentified program"}." : null);
    }

    // Older or incomplete replies cannot establish a clean decision.
    static AdminBlockStatus? Read(AdminReply? reply) =>
        reply is { Status: AdminStatus.Ok, Result: { } result }
            && result["blocked"] is JsonValue b && b.TryGetValue<bool>(out var blocked)
            && result["generation"] is JsonValue g && g.TryGetValue<long>(out var generation) && generation >= 0
            ? new(blocked, generation) : null;
}
