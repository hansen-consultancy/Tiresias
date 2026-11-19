using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>A part of the app Home can list.</summary>
public enum HomeArea
{
    UserSecrets,
    Services,
    EnvironmentVariables,
    Activity,
}

/// <summary>
/// What Home knows about this machine, read while locked: names and counts, never a value. A
/// <c>null</c> fact couldn't be read.
/// </summary>
/// <param name="Services">The vault's services.</param>
/// <param name="SealedUserSecrets">Some project's <c>secrets.json</c> is sealed.</param>
/// <param name="ProjectFolders">The secrets editor has a project folder to scan.</param>
/// <param name="SealedVariables">Environment variables are sealed.</param>
/// <param name="ActivityRecorded">The activity or audit log has a record.</param>
/// <param name="Fixes">The fixes of the status page's last run, whose windows stay reachable.</param>
/// <param name="Opened">Areas opened from <i>What do you need?</i> this session.</param>
public sealed record HomeFacts(
    int? Services,
    bool? SealedUserSecrets,
    bool? ProjectFolders,
    bool? SealedVariables,
    bool? ActivityRecorded,
    IReadOnlyCollection<DoctorFix> Fixes,
    IReadOnlyCollection<HomeArea> Opened);

/// <summary>
/// Home lists only the areas this machine uses; the rest are one step away through <i>What do you
/// need?</i> (docs/what-do-you-need.md). It never hides an area with content or a finding, and a
/// fact it couldn't read shows the area rather than hiding it.
/// </summary>
public static class HomeAreas
{
    public static IReadOnlySet<HomeArea> Plan(HomeFacts facts)
    {
        var areas = new HashSet<HomeArea>(facts.Opened);
        if (facts.Services is null or > 0)
            areas.Add(HomeArea.Services);
        if (facts.SealedUserSecrets is null or true || facts.ProjectFolders is null or true)
            areas.Add(HomeArea.UserSecrets);
        if (facts.SealedVariables is null or true)
            areas.Add(HomeArea.EnvironmentVariables);
        if (facts.ActivityRecorded is null or true)
            areas.Add(HomeArea.Activity);
        foreach (var fix in facts.Fixes)
            if (Of(fix) is { } area)
                areas.Add(area);
        return areas;
    }

    /// <summary>The area a fix opens; <c>null</c> for one that opens none (a guide, a command to copy).</summary>
    public static HomeArea? Of(DoctorFix fix) => fix switch
    {
        ReviewUserSecrets or SealUserSecrets => HomeArea.UserSecrets,
        ProtectVariables or SealVariable => HomeArea.EnvironmentVariables,
        SetUpSqlServer or SetUpRaven or AddService => HomeArea.Services,
        _ => null,
    };

    /// <summary>The area an option of <i>What do you need?</i> opens.</summary>
    public static HomeArea? Of(NeedStep step) => step switch
    {
        NeedStep.AddService or NeedStep.SetUpSqlServer or NeedStep.SetUpRaven => HomeArea.Services,
        NeedStep.OpenEnvironment => HomeArea.EnvironmentVariables,
        NeedStep.OpenSecrets => HomeArea.UserSecrets,
        _ => null,
    };
}
