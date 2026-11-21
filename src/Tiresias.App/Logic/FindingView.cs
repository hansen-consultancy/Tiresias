using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>What a finding's fix button does in the app.</summary>
public enum FixAction
{
    OpenSecrets,
    OpenEnvironment,
    SetUpSqlServer,
    SetUpRaven,
    /// <summary>A step outside the app (a package to reference): the command goes to the clipboard.</summary>
    CopyCommand,
    /// <summary>Seal a registry token from its file, after a yes that says the token is read once.</summary>
    SealToken,
    /// <summary>Edit... on a RavenDB service, to pick a new certificate.</summary>
    ReplaceRaven,
    /// <summary>Environment variables, with the variable checked and the placeholder section in view.</summary>
    UsePlaceholder,
    /// <summary>Remove an extension with its host's command, after the user approves.</summary>
    RemoveExtension,
    /// <summary>Show a file in Explorer.</summary>
    RevealFile,
    /// <summary>Turn a log-on entry off the way Task Manager does, after the user approves.</summary>
    DisableStartup,
    /// <summary>Settings, Apps, Startup, for a machine-wide entry only an administrator can turn off.</summary>
    OpenStartupSettings,
    /// <summary>Save one of the user's uninstall entries to a <c>.reg</c> file and delete it, after the user approves.</summary>
    RemoveEntry,
    /// <summary>Take a program off the blocklist.</summary>
    Unblock,
    /// <summary>The Services page's add form, its address filled in.</summary>
    AddService,
    /// <summary>Settings, Apps, Installed apps, where the user uninstalls a program.</summary>
    OpenInstalledApps,
}

/// <summary>
/// How the status page shows the doctor's lines: findings first, those of one kind as one group,
/// dismissed ones apart, then the rest.
/// </summary>
public static class FindingView
{
    /// <param name="Open">Groups of findings not dismissed, failures first, then the largest.</param>
    /// <param name="Dismissed">Findings the user set aside, grouped by kind and reason.</param>
    /// <param name="Others">Every other line: Tiresias's own health, and checks that passed.</param>
    public sealed record Split(IReadOnlyList<IReadOnlyList<DoctorCheck>> Open, IReadOnlyList<DismissedGroup> Dismissed, IReadOnlyList<DoctorCheck> Others);

    /// <summary>Findings dismissed together: one kind, one reason, and the keys that bring them back.</summary>
    public sealed record DismissedGroup(string Title, string Reason, IReadOnlyList<string> Keys);

    public static Split Of(IReadOnlyList<DoctorCheck> checks, Dismissals dismissals)
    {
        var findings = checks.Where(c => c.IsFinding).Select(c => (Check: c, Dismissal: dismissals.For(c))).ToArray();
        var open = findings.Where(f => f.Dismissal is null).Select(f => f.Check)
            .GroupBy(KindOf)
            .Select(g => (IReadOnlyList<DoctorCheck>)[.. g])
            .OrderByDescending(g => g[0].Status).ThenByDescending(g => g.Count);
        var dismissed = findings.Where(f => f.Dismissal is not null)
            .GroupBy(f => (Kind: KindOf(f.Check), f.Dismissal!.Reason))
            .Select(g => new DismissedGroup(Title([.. g.Select(f => f.Check)]), g.Key.Reason, [.. g.Select(f => f.Dismissal!.Key)]));
        return new([.. open], [.. dismissed], [.. checks.Where(c => !c.IsFinding)]);
    }

    /// <summary>Findings of one kind group together; a line without a kind stands alone.</summary>
    static (string? Kind, DoctorStatus Status, string? Name) KindOf(DoctorCheck check) =>
        (check.Kind, check.Status, check.Kind is null ? check.Name : null);

    /// <summary>A group's heading: the line itself when it is one, else how many and of what kind.</summary>
    public static string Title(IReadOnlyList<DoctorCheck> group) =>
        group.Count == 1 || group[0].Kind is null ? group[0].Name : $"{group.Count} {group[0].Kind}";

    /// <summary>What every line in the group says, or empty when they differ (each line then says its own).</summary>
    public static string Detail(IReadOnlyList<DoctorCheck> group) =>
        group.All(c => c.Detail == group[0].Detail) ? group[0].Detail : "";

    /// <summary>The button for a fix, and the string key of its label; <c>null</c> when the app has no step for it.</summary>
    public static (FixAction Action, string Label)? Button(DoctorFix? fix) => fix switch
    {
        ReviewUserSecrets => (FixAction.OpenSecrets, "Finding_FixSecrets"),
        ProtectVariables => (FixAction.OpenEnvironment, "Finding_FixVariables"),
        SetUpSqlServer => (FixAction.SetUpSqlServer, "Finding_FixSql"),
        SetUpRaven => (FixAction.SetUpRaven, "Finding_FixRaven"),
        ReferenceConfigurationPackage => (FixAction.CopyCommand, "Finding_FixCopy"),
        RemoveTokenFromRemote => (FixAction.CopyCommand, "Finding_FixCopy"),
        ImportNuGetCredentials { InProfile: true } => (FixAction.OpenEnvironment, "Finding_FixNuGet"),
        ImportNuGetCredentials => (FixAction.CopyCommand, "Finding_FixCopy"),
        SealRegistryToken => (FixAction.SealToken, "Finding_FixToken"),
        ReplaceRavenCertificate => (FixAction.ReplaceRaven, "Finding_FixRavenReplace"),
        UsePlaceholder => (FixAction.UsePlaceholder, "Finding_FixPlaceholder"),
        RemoveExtension => (FixAction.RemoveExtension, "Finding_FixRemoveExtension"),
        RevealFile => (FixAction.RevealFile, "Finding_FixReveal"),
        DisableStartup { Machine: false } => (FixAction.DisableStartup, "Finding_FixDisableStartup"),
        DisableStartup => (FixAction.OpenStartupSettings, "Finding_FixStartupSettings"),
        RemoveEntry { Machine: false } => (FixAction.RemoveEntry, "Finding_FixRemoveEntry"),
        RemoveEntry or Repair { Command: not null } => (FixAction.CopyCommand, "Finding_FixCopy"),
        UnblockProgram => (FixAction.Unblock, "Finding_FixUnblock"),
        RunThroughExec { Setup: not null } => (FixAction.AddService, "Finding_FixGitHubApp"),
        RunThroughExec => (FixAction.CopyCommand, "Finding_FixCopy"),
        UninstallApp => (FixAction.OpenInstalledApps, "Finding_FixInstalledApps"),
        _ => null,
    };

    /// <summary>Where the delivery sits and where the fix takes it, as <c>E5/C3 → E2/C1</c>.</summary>
    public static string Moves(DoctorCheck check) => check switch
    {
        { Now: { } now, Better: { } better } => $"{now} → {better}",
        { Now: { } now } => now.ToString(),
        _ => "",
    };
}
