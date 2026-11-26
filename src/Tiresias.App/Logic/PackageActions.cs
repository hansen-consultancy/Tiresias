using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>A package fix as the app offers it: its button, and the question that asks before anything runs.</summary>
/// <param name="Button">The string key of its button's label; formatted with the newer version for an update that names one.</param>
/// <param name="Heading">The question's heading key, formatted with the package's name.</param>
/// <param name="Body">The question's body key, formatted with the exact command.</param>
/// <param name="Action">The key of the question's go-ahead button.</param>
public sealed record PackageAsk(string Button, string Heading, string Body, string Action);

/// <summary>
/// Which package fixes the Installed page offers for a program or a global tool (docs/attack-surface.md#findings),
/// and how each asks first. The commands themselves are <see cref="Packages"/>'.
/// </summary>
public static class PackageActions
{
    /// <summary>
    /// Update and uninstall through winget, for a program it installed. On a managed PC machine-wide
    /// software is the administrator's, so it gets none, as it gets no finding.
    /// </summary>
    public static (PackageFix? Update, PackageFix? Uninstall) For(UninstallEntry entry, IReadOnlyList<WingetPackage> winget, bool managed) =>
        entry.Machine && managed || Packages.Of(entry, winget) is not { } package
            ? (null, null)
            : (Packages.Update(package, entry.Machine), Packages.Uninstall(package, entry.Machine));

    public static (PackageFix? Update, PackageFix? Uninstall) For(GlobalTool tool) => (Packages.Update(tool), Packages.Uninstall(tool));

    /// <summary>The version an update moves to, for its button; <c>null</c> when the manager picks the newest itself.</summary>
    public static string? Target(PackageFix fix) => fix switch
    {
        { Change: PackageChange.Update, Command: { Manager: "winget", Arguments: [.., "--version", var version] } } => version,
        { Change: PackageChange.Update, Command: { Manager: "npm", Arguments: [.., var package] } } when package.LastIndexOf('@', StringComparison.Ordinal) > 0 =>
            package[(package.LastIndexOf('@', StringComparison.Ordinal) + 1)..],
        _ => null,
    };

    /// <summary>How a fix asks: an administrator's change says so, since Windows will ask for one.</summary>
    public static PackageAsk Ask(PackageFix fix)
    {
        var admin = fix.Command.Administrator;
        return fix.Change switch
        {
            PackageChange.Update => new(Target(fix) is null ? "Package_UpdateNewest" : "Package_UpdateTo", "Package_UpdateHeading",
                admin ? "Package_UpdateBodyAdmin" : "Package_UpdateBody", "Package_Update"),
            PackageChange.Uninstall => new("Package_Uninstall", "Package_UninstallHeading",
                admin ? "Package_UninstallBodyAdmin" : "Package_UninstallBody", "Package_UninstallAction"),
            _ => new("Finding_FixRepair", "Package_RepairHeading", admin ? "Package_RepairBodyAdmin" : "Package_RepairBody", "Package_RepairAction"),
        };
    }

    /// <summary>
    /// What to tell the user after it ran, by the manager's exit code (0 is success); <c>null</c> when
    /// it didn't start or the administrator prompt was declined.
    /// </summary>
    public static (string Key, bool Done) Outcome(int? exitCode) => exitCode switch
    {
        0 => ("Package_Done", true),
        null => ("Package_NotStarted", false),
        _ => ("Package_Failed", false),
    };
}
