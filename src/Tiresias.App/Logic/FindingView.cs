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
}

/// <summary>How the status page shows the doctor's lines: findings first, dismissed ones apart, then the rest.</summary>
public static class FindingView
{
    /// <param name="Open">Findings not dismissed, failures before warnings.</param>
    /// <param name="Dismissed">Findings the user set aside, with why.</param>
    /// <param name="Others">Every other line: Tiresias's own health, and checks that passed.</param>
    public sealed record Split(IReadOnlyList<DoctorCheck> Open, IReadOnlyList<(DoctorCheck Check, Dismissal Dismissal)> Dismissed, IReadOnlyList<DoctorCheck> Others);

    public static Split Of(IReadOnlyList<DoctorCheck> checks, Dismissals dismissals)
    {
        var findings = checks.Where(c => c.IsFinding).Select(c => (Check: c, Dismissal: dismissals.For(c))).ToArray();
        return new(
            [.. findings.Where(f => f.Dismissal is null).Select(f => f.Check).OrderByDescending(c => c.Status)],
            [.. findings.Where(f => f.Dismissal is not null).Select(f => (f.Check, f.Dismissal!))],
            [.. checks.Where(c => !c.IsFinding)]);
    }

    /// <summary>The button for a fix, and the string key of its label; <c>null</c> when the app has no step for it.</summary>
    public static (FixAction Action, string Label)? Button(DoctorFix? fix) => fix switch
    {
        ReviewUserSecrets => (FixAction.OpenSecrets, "Finding_FixSecrets"),
        ProtectVariables => (FixAction.OpenEnvironment, "Finding_FixVariables"),
        SetUpSqlServer => (FixAction.SetUpSqlServer, "Finding_FixSql"),
        SetUpRaven => (FixAction.SetUpRaven, "Finding_FixRaven"),
        ReferenceConfigurationPackage => (FixAction.CopyCommand, "Finding_FixCopy"),
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
