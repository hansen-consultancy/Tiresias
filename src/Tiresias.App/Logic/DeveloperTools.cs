namespace Tiresias.App.Logic;

/// <summary>What the About page's <i>Show developer tools</i> says.</summary>
public enum DeveloperToolsSetting
{
    Auto,
    On,
    Off,
}

/// <summary>Something on this PC that only a developer has (docs/developer-tools.md#signals).</summary>
public enum DeveloperSignal
{
    DotNetSdk,
    UserSecrets,
    Git,
    VisualStudio,
    Rider,
    VsCode,
    Wsl,
    Docker,
    SealedVariables,
    VaultServices,
    ProjectFolders,
}

/// <summary>Whether the developer tools show, and the signals that showed them (empty unless Auto decided).</summary>
public sealed record DeveloperView(bool Shown, IReadOnlyList<DeveloperSignal> Because);

/// <summary>
/// Developer tools appear on a developer's PC without a mode to choose: any signal shows them, and
/// the setting overrides. They only ever add: findings, Warn/Fail lines and areas in use show anyway.
/// </summary>
public static class DeveloperTools
{
    /// <param name="signals">Each signal read; <c>null</c> when it couldn't be read, which counts as present, as in <see cref="HomeAreas"/>.</param>
    public static DeveloperView Plan(IReadOnlyDictionary<DeveloperSignal, bool?> signals, DeveloperToolsSetting setting) => setting switch
    {
        DeveloperToolsSetting.On => new(true, []),
        DeveloperToolsSetting.Off => new(false, []),
        _ => signals.Where(s => s.Value is null or true).Select(s => s.Key).Order().ToArray() is { Length: > 0 } found
            ? new(true, found)
            : new(false, []),
    };

    /// <summary>The string key that says a signal, as the end of "Developer tools are shown because ...".</summary>
    public static string Key(DeveloperSignal signal) => signal switch
    {
        DeveloperSignal.DotNetSdk => "DevSignal_DotNetSdk",
        DeveloperSignal.UserSecrets => "DevSignal_UserSecrets",
        DeveloperSignal.Git => "DevSignal_Git",
        DeveloperSignal.VisualStudio => "DevSignal_VisualStudio",
        DeveloperSignal.Rider => "DevSignal_Rider",
        DeveloperSignal.VsCode => "DevSignal_VsCode",
        DeveloperSignal.Wsl => "DevSignal_Wsl",
        DeveloperSignal.Docker => "DevSignal_Docker",
        DeveloperSignal.SealedVariables => "DevSignal_SealedVariables",
        DeveloperSignal.VaultServices => "DevSignal_VaultServices",
        DeveloperSignal.ProjectFolders => "DevSignal_ProjectFolders",
        _ => throw new ArgumentOutOfRangeException(nameof(signal), signal, null),
    };

    /// <summary>Home's line saying why the tools appeared: only when Auto showed them and the user hasn't closed it.</summary>
    public static bool ShowHomeLine(DeveloperView view, bool noted) => view.Because.Count > 0 && !noted;
}
