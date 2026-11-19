using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Where an option of <i>What do you need?</i> leads in the app.</summary>
public enum NeedStep
{
    /// <summary>The Services window's add form, its address filled in when the option names one.</summary>
    AddService,
    SetUpSqlServer,
    SetUpRaven,
    OpenEnvironment,
    OpenSecrets,
    /// <summary>An option with no secret (E1): the guide, in the browser.</summary>
    OpenGuide,
}

/// <summary>How <i>What do you need?</i> shows the catalogue's options.</summary>
public static class NeedView
{
    /// <summary>The step an option's action starts, and the string key of its button.</summary>
    public static (NeedStep Step, string Label) Button(DoctorFix action) => action switch
    {
        AddService { Kind: ServiceKind.SqlServer } => (NeedStep.SetUpSqlServer, "Needs_SetUpSql"),
        AddService { Kind: ServiceKind.RavenDb } => (NeedStep.SetUpRaven, "Needs_SetUpRaven"),
        AddService => (NeedStep.AddService, "Needs_AddService"),
        SealVariable or ProtectVariables => (NeedStep.OpenEnvironment, "Needs_OpenEnvironment"),
        SealUserSecrets or ReviewUserSecrets => (NeedStep.OpenSecrets, "Needs_OpenSecrets"),
        FollowGuide => (NeedStep.OpenGuide, "Needs_OpenGuide"),
        _ => throw new ArgumentOutOfRangeException(nameof(action), action.GetType().Name, "No step in the app for this action."),
    };

    /// <summary>The first need opens when the words found it; with nothing found every need stays closed, so the whole list fits.</summary>
    public static bool Expanded(int index, NeedMatch match) => index == 0 && match.Score > 0;

    /// <summary>The guide's address on the repository's default branch.</summary>
    public static string GuideUrl(string repository) => $"{repository}/blob/main/{FollowGuide.Page}";
}
