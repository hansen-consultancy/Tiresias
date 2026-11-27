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
    /// <summary>Thaw a program the admin tier froze (a UAC prompt), then take it off the blocklist.</summary>
    Thaw,
    /// <summary>The Services page's add form, its address filled in.</summary>
    AddService,
    /// <summary>Run a package manager's command (a winget repair), after the user approves it.</summary>
    RunPackage,
    /// <summary>The Installed page: the whole list, unused programs first.</summary>
    OpenInstalledList,
    /// <summary>The Startup page: everything that starts at sign-in.</summary>
    OpenStartupList,
    /// <summary>The About page, where the Alerts card fixes, tests or removes a sink.</summary>
    OpenAlerts,
    /// <summary>The steps on a page in the repository, in the browser: they need an administrator, or Docker quit, not Tiresias.</summary>
    OpenGuide,
}

/// <summary>
/// How the status page shows the doctor's lines: findings first, those of one kind as one group,
/// dismissed ones apart, then the rest.
/// </summary>
public static class FindingView
{
    /// <param name="Held">Groups of findings not dismissed about how credentials are held, failures first, then the largest.</param>
    /// <param name="Reach">The same about what can reach them (<see cref="DoctorCheck.Surface"/>), ranked apart: one
    /// order across both would rank a plaintext password against an old extension (docs/attack-surface.md#ranking).</param>
    /// <param name="Dismissed">Findings the user set aside, grouped by kind and reason, then one group per trusted publisher, even one hiding nothing now.</param>
    /// <param name="Others">Every other line: Tiresias's own health, and checks that passed.</param>
    public sealed record Split(IReadOnlyList<IReadOnlyList<DoctorCheck>> Held, IReadOnlyList<IReadOnlyList<DoctorCheck>> Reach,
        IReadOnlyList<DismissedGroup> Dismissed, IReadOnlyList<DoctorCheck> Others)
    {
        /// <summary>Every open group, as Home numbers them: how credentials are held, then what can reach them.</summary>
        public IReadOnlyList<IReadOnlyList<DoctorCheck>> Open => [.. Held, .. Reach];
    }

    /// <summary>Findings dismissed together: one kind, one reason, and the keys that bring them back.</summary>
    /// <param name="Publisher">For the findings a trusted publisher hides: that publisher, whose trust is undone to bring them back.</param>
    public sealed record DismissedGroup(string Title, string Reason, IReadOnlyList<string> Keys, TrustedPublisher? Publisher = null);

    /// <param name="developerTools">Developer tools show. Without them, a line reads as its <see cref="DoctorCheck.WithoutDeveloperTools"/>,
    /// a developer check's passing line is left out and a solo note shows as passed; findings and Warn/Fail lines show either way
    /// (docs/developer-tools.md).</param>
    public static Split Of(IReadOnlyList<DoctorCheck> checks, Dismissals dismissals, bool developerTools = true)
    {
        if (!developerTools)
            checks = [.. checks
                .Select(c => c.WithoutDeveloperTools ?? c)
                .Where(c => c.IsFinding || !c.ForDevelopers || c.Status != DoctorStatus.Ok)
                .Select(c => c.SoloNote && !c.IsFinding ? c with { Status = DoctorStatus.Ok } : c)];
        var findings = checks.Where(c => c.IsFinding).Select(c => (Check: c, Dismissal: dismissals.For(c))).ToArray();
        var open = findings.Where(f => f.Dismissal is null).Select(f => f.Check)
            .GroupBy(KindOf)
            .Select(g => (IReadOnlyList<DoctorCheck>)[.. g])
            .OrderByDescending(g => g[0].Status).ThenByDescending(g => g.Count)
            .ToLookup(g => g[0].Surface);
        var dismissed = findings.Where(f => f.Dismissal is { Trusted: null })
            .GroupBy(f => (Kind: KindOf(f.Check), f.Dismissal!.Reason))
            .Select(g => new DismissedGroup(Title([.. g.Select(f => f.Check)]), g.Key.Reason, [.. g.Select(f => f.Dismissal!.Key)]));
        var trusted = dismissals.Publishers.Select(p => new DismissedGroup(p.Name, "",
            [.. findings.Where(f => f.Dismissal?.Trusted?.Key == p.Key).Select(f => f.Dismissal!.Key)], p));
        return new([.. open[false]], [.. open[true]], [.. dismissed, .. trusted], [.. checks.Where(c => !c.IsFinding)]);
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
        RemoveExtensionByHand => (FixAction.CopyCommand, "Finding_FixCopy"),
        RevealFile => (FixAction.RevealFile, "Finding_FixReveal"),
        DisableStartup { Machine: false } => (FixAction.DisableStartup, "Finding_FixDisableStartup"),
        DisableStartup => (FixAction.OpenStartupSettings, "Finding_FixStartupSettings"),
        RemoveEntry { Machine: false } => (FixAction.RemoveEntry, "Finding_FixRemoveEntry"),
        RemoveEntry => (FixAction.CopyCommand, "Finding_FixCopy"),
        PackageFix package => (FixAction.RunPackage, PackageActions.Ask(package).Button),
        UnblockProgram => (FixAction.Unblock, "Finding_FixUnblock"),
        ThawProgram => (FixAction.Thaw, "Finding_FixThaw"),
        RunThroughExec { Setup: not null } => (FixAction.AddService, "Finding_FixGitHubApp"),
        RunThroughExec => (FixAction.CopyCommand, "Finding_FixCopy"),
        UninstallApp => (FixAction.OpenInstalledList, "Finding_FixInstalledList"),
        ReviewStartup => (FixAction.OpenStartupList, "Finding_FixStartupList"),
        ReviewAlerts => (FixAction.OpenAlerts, "Finding_FixAlerts"),
        ReachGuide => (FixAction.OpenGuide, "Finding_FixReachGuide"),
        InjectAtRunTime => (FixAction.CopyCommand, "Finding_FixCopy"),
        UpdateGlobalTool or UninstallGlobalTool => (FixAction.CopyCommand, "Finding_FixCopy"),
        ChangeToolSetting => (FixAction.CopyCommand, "Finding_FixCopy"),
        _ => null,
    };

    /// <summary>
    /// A row's button: a finding's own, or for a group the one its members share when it opens a
    /// list rather than acting on one of them, so unused programs are one line with one button.
    /// </summary>
    public static (FixAction Action, string Label)? GroupButton(IReadOnlyList<DoctorCheck> group) =>
        group.Count == 1 ? Button(group[0].Fix)
        : group.Select(c => Button(c.Fix)).Distinct().ToArray() is [{ Action: FixAction.OpenInstalledList or FixAction.OpenStartupList } shared] ? shared
        : null;

    /// <summary>
    /// The publisher a row offers to trust: the checked signer every finding in it shares, when trust
    /// may hide each of them. A row mixing signers offers none; its members each offer their own.
    /// </summary>
    public static Publisher? Trustable(IReadOnlyList<DoctorCheck> group) =>
        group.Count > 0 && group.All(c => c is { TrustHides: true, Signer: not null }) && group.Select(c => c.Signer!.Key).Distinct().Count() == 1
            ? group[0].Signer : null;

    /// <summary>The page a <see cref="ReachGuide"/> opens: its findings, which say how to close each path.</summary>
    public static string ReachGuideUrl(string repository) => $"{repository}/blob/main/{ReachGuide.Page}#findings";

    /// <summary>Where the delivery sits and where the fix takes it, as <c>E5/C3 → E2/C1</c>.</summary>
    public static string Moves(DoctorCheck check) => check switch
    {
        { Now: { } now, Better: { } better } => $"{now} → {better}",
        { Now: { } now } => now.ToString(),
        _ => "",
    };
}
