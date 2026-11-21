using System.Globalization;
using Tiresias.Protocol;

namespace Tiresias.AdminTier;

public enum AdminTierState
{
    NotInstalled,
    Running,
    /// <summary>Installed, but the service isn't running: nothing it does happens.</summary>
    Stopped,
    /// <summary>The service runs, but no answer came from it: it hung, or something else holds the pipe name.</summary>
    NotAnswering,
    /// <summary>Running an older version than the app: <b>Update</b> runs the install step again.</summary>
    Older,
}

/// <summary>What the app and <c>tir doctor</c> know of the admin tier, read without a prompt.</summary>
/// <param name="Running">The Service Control Manager says the service runs.</param>
/// <param name="Status">Its answer to <see cref="AdminOps.Status"/>, taken only from the process the SCM runs as the service; <c>null</c> when none came.</param>
/// <param name="AppVersion">The version of the app (or tir) asking, to tell an older service.</param>
public sealed record AdminTierFacts(bool Installed, bool Running, AdminStatusResult? Status, string AppVersion)
{
    public AdminTierState State =>
        !Installed ? AdminTierState.NotInstalled
        : !Running ? AdminTierState.Stopped
        : Status is null ? AdminTierState.NotAnswering
        : AppVersions.Compare(Status.Version, AppVersion) < 0 ? AdminTierState.Older
        : AdminTierState.Running;

    /// <summary>The features on, as words ("decoys held, listening"), or "none yet".</summary>
    public string Features => Status?.Features is { } f
        ? string.Join(", ", new[] { (f.DecoysHeld, "decoys held"), (f.Listening, "listening"), (f.Auditing, "auditing") }
            .Where(x => x.Item1).Select(x => x.Item2).DefaultIfEmpty("none yet"))
        : "unknown";
}

/// <summary>Orders the app's versions: "0.2.1" &gt; "0.2.1-preview.3" &gt; "0.2.0"; build metadata after '+' is ignored.</summary>
public static class AppVersions
{
    public static int Compare(string a, string b)
    {
        var (coreA, preA) = Split(a);
        var (coreB, preB) = Split(b);
        var byCore = coreA.CompareTo(coreB);
        if (byCore != 0)
            return byCore;
        if (preA is null || preB is null)
            return preA is null ? (preB is null ? 0 : 1) : -1;
        var idsA = preA.Split('.');
        var idsB = preB.Split('.');
        for (var i = 0; i < Math.Min(idsA.Length, idsB.Length); i++)
        {
            var numA = int.TryParse(idsA[i], NumberStyles.None, CultureInfo.InvariantCulture, out var na);
            var numB = int.TryParse(idsB[i], NumberStyles.None, CultureInfo.InvariantCulture, out var nb);
            var byId = numA && numB ? na.CompareTo(nb)
                : numA ? -1
                : numB ? 1
                : string.CompareOrdinal(idsA[i], idsB[i]);
            if (byId != 0)
                return Math.Sign(byId);
        }
        return idsA.Length.CompareTo(idsB.Length);
    }

    static (Version Core, string? Pre) Split(string version)
    {
        var noBuild = version.Split('+', 2)[0];
        var parts = noBuild.Split('-', 2);
        var core = Version.TryParse(parts[0], out var v) ? v : new Version(0, 0);
        // "1.2" and "1.2.0" are the same version.
        core = new Version(core.Major, core.Minor, Math.Max(core.Build, 0));
        return (core, parts.Length == 2 && parts[1].Length > 0 ? parts[1] : null);
    }
}
