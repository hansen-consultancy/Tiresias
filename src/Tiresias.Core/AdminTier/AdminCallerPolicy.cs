using System.Text.Json.Nodes;
using Tiresias.Protocol;

namespace Tiresias.AdminTier;

/// <summary>Who is on the other end of the admin pipe, as the service read it from the client process's token.</summary>
/// <param name="UserSid">The token's user. Every action is keyed by it.</param>
/// <param name="SessionId">The token's session.</param>
/// <param name="SessionUserSid">Who is signed in to that session; <c>null</c> when nobody is, or it can't be told.</param>
/// <param name="Elevated">The token is elevated: it took a UAC prompt, which a program running as the user can't click.</param>
/// <param name="IsService">The token is a service's: SYSTEM, LocalService, NetworkService, or one carrying the SERVICE group.</param>
public sealed record AdminCaller(string UserSid, int SessionId, string? SessionUserSid, bool Elevated, bool IsService);

/// <param name="Reason">Why it was refused, for the reply and the action log; <c>null</c> when allowed. Never a value from the request.</param>
/// <param name="ActingFor">Whose things the request acts on when allowed: the caller's user, or, for an elevated caller, the user signed in to its session.</param>
public sealed record AdminDecision(bool Allowed, string? Reason, string? ActingFor = null)
{
    public static readonly AdminDecision Allow = new(true, null);

    public static AdminDecision Refuse(string reason) => new(false, reason);
}

/// <summary>
/// Whether the admin tier's service acts on a request (docs/admin-tier.md, <i>Principles</i>). In
/// order: the protocol version, the op, the caller (no services, no one in another user's session),
/// elevation for an op that weakens protection, whether this service has the op yet, and the op's
/// arguments, each by name and type, none missing and none extra. Anything refused is refused
/// before the service does anything.
/// </summary>
public static class AdminCallerPolicy
{
    /// <summary>One argument: whether a value is in range for it.</summary>
    delegate bool ArgCheck(JsonNode? value);

    /// <param name="Elevated">The op weakens protection, so it needs a UAC prompt.</param>
    /// <param name="Args">Its arguments by name; <c>null</c> while the op isn't built, so it is refused.</param>
    sealed record OpRule(bool Elevated, IReadOnlyDictionary<string, ArgCheck>? Args);

    static readonly IReadOnlyDictionary<string, ArgCheck> NoArgs = new Dictionary<string, ArgCheck>();

    static readonly Dictionary<string, OpRule> Rules = new(StringComparer.Ordinal)
    {
        [AdminOps.Status] = new(false, NoArgs),
        [AdminOps.EventsWait] = new(false, new Dictionary<string, ArgCheck> { ["after"] = AdminArgs.Cursor, ["wait"] = AdminArgs.Wait }),
        [AdminOps.EventsHistory] = new(false, new Dictionary<string, ArgCheck> { ["after"] = AdminArgs.Cursor }),
        [AdminOps.EventsReview] = new(true, new Dictionary<string, ArgCheck> { ["through"] = AdminArgs.Cursor }),
        [AdminOps.BlocksCheck] = new(false, new Dictionary<string, ArgCheck>
        {
            ["program"] = value => value is null || AdminArgs.Program(value),
            ["sha256"] = value => value is null || AdminArgs.Digest(value),
        }),
        [AdminOps.BlocksList] = new(false, new Dictionary<string, ArgCheck> { ["after"] = value => value is null || AdminArgs.Program(value) }),
        [AdminOps.BlocksUnblock] = new(true, new Dictionary<string, ArgCheck> { ["program"] = AdminArgs.Program }),
        [AdminOps.DecoysAdopt] = new(true, new Dictionary<string, ArgCheck> { ["owner"] = AdminArgs.Owner, ["set"] = AdminArgs.Set, ["files"] = AdminArgs.Files }),
        [AdminOps.DecoysStatus] = new(false, NoArgs),
        [AdminOps.Freeze] = new(false, new Dictionary<string, ArgCheck> { ["pid"] = AdminArgs.Pid }),
        [AdminOps.Thaw] = new(true, new Dictionary<string, ArgCheck> { ["program"] = AdminArgs.Program }),
        [AdminOps.DecoysRelease] = new(true, NoArgs),
        [AdminOps.DecoysReleaseCommit] = new(true, new Dictionary<string, ArgCheck> { ["receipt"] = AdminArgs.Digest }),
        [AdminOps.LastRun] = new(false, new Dictionary<string, ArgCheck> { ["paths"] = AdminArgs.RunPaths }),
        [AdminOps.Teardown] = new(true, NoArgs),
    };

    /// <summary>The op, if it is one of <see cref="AdminOps"/>; otherwise <c>null</c>, so a caller's text never reaches a log.</summary>
    public static string? KnownOp(string? op) => op is not null && Rules.ContainsKey(op) ? op : null;

    /// <summary>The ops that weaken protection: an unelevated caller is refused them.</summary>
    public static bool NeedsElevation(string op) => Rules.TryGetValue(op, out var rule) && rule.Elevated;

    public static AdminDecision Decide(AdminRequest request, AdminCaller caller)
    {
        if (request.Version != AdminWire.ProtocolVersion)
            return AdminDecision.Refuse($"protocol version {request.Version} isn't spoken here; this service speaks {AdminWire.ProtocolVersion}");
        if (request.Op is null || !Rules.TryGetValue(request.Op, out var rule))
            return AdminDecision.Refuse("unknown op");
        if (caller.IsService || caller.SessionId == 0)
            return AdminDecision.Refuse("services can't call the admin tier");
        // Over the shoulder, a standard user's UAC prompt is approved with an administrator's
        // password: the elevated caller is that administrator, in the user's session, acting for
        // the user. An administrator could do all of it anyway; an unelevated caller never acts
        // for anyone but itself.
        if (caller.SessionUserSid is null
            || (!caller.Elevated && !string.Equals(caller.SessionUserSid, caller.UserSid, StringComparison.OrdinalIgnoreCase))
            || !AdminArgs.UserSid(caller.SessionUserSid))
            return AdminDecision.Refuse("the caller isn't the user signed in to its session");
        if (rule.Elevated && !caller.Elevated)
            return AdminDecision.Refuse($"{request.Op} needs an elevated caller");
        if (rule.Args is null)
            return AdminDecision.Refuse($"{request.Op} isn't available in this version of the service");
        var decision = Validate(request.Args, rule.Args);
        if (decision.Allowed && request.Op == AdminOps.DecoysAdopt &&
            !string.Equals(request.Args!["owner"]!.GetValue<string>(), caller.SessionUserSid, StringComparison.OrdinalIgnoreCase))
            return AdminDecision.Refuse("the enrollment belongs to another session user");
        return decision.Allowed ? decision with { ActingFor = caller.SessionUserSid.ToUpperInvariant() } : decision;
    }

    static AdminDecision Validate(JsonObject? args, IReadOnlyDictionary<string, ArgCheck> expected)
    {
        var given = args ?? [];
        foreach (var (name, _) in given)
            if (!expected.ContainsKey(name))
                return AdminDecision.Refuse("unexpected argument");
        foreach (var (name, check) in expected)
        {
            if (!given.TryGetPropertyValue(name, out var value))
                return AdminDecision.Refuse($"missing argument {name}");
            if (!check(value))
                return AdminDecision.Refuse($"argument {name} is out of range");
        }
        return AdminDecision.Allow;
    }
}
