using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>A program winget knows, from <c>winget list --source winget</c>: its name, package id, version and any newer one.</summary>
public sealed record WingetPackage(string Name, string Id, string? Version, string? Available = null);

/// <summary>
/// A package manager's command as the app runs it: the manager and an argument list, never a shell
/// string, because the package id comes from the machine. Built only by <see cref="Packages"/>,
/// which takes plain package ids and versions only.
/// </summary>
/// <param name="Administrator">It changes software installed for everyone, so it runs elevated.</param>
public sealed record PackageCommand(string Manager, IReadOnlyList<string> Arguments, bool Administrator = false)
{
    /// <summary>The command as the user reads it before approving, and as <c>tir doctor</c> prints it.</summary>
    public string Text => string.Join(' ', [Manager, .. Arguments]);

    /// <summary>What to start: <c>npm</c> is a batch file, so it goes through <c>cmd</c>; the others are programs.</summary>
    public (string Program, IReadOnlyList<string> Arguments) Start =>
        Manager == "npm" ? ("cmd.exe", ["/d", "/c", "npm", .. Arguments]) : (Manager, Arguments);

    public bool Equals(PackageCommand? other) =>
        other is not null && Manager == other.Manager && Administrator == other.Administrator && Arguments.SequenceEqual(other.Arguments);

    public override int GetHashCode() => HashCode.Combine(Manager, Administrator, Text);
}

/// <summary>What a <see cref="PackageFix"/> does to the package.</summary>
public enum PackageChange
{
    Update,
    Uninstall,
    /// <summary>Reinstall the installed version over itself, which restores a missing uninstaller.</summary>
    Repair,
}

/// <summary>
/// Update, uninstall or repair a package with the manager that installed it. The app runs
/// <see cref="Command"/> only after the user approves it, never from a scan.
/// </summary>
/// <param name="Name">What the user calls it: the program's name, or the tool's package id.</param>
public sealed record PackageFix(PackageChange Change, string Name, PackageCommand Command) : DoctorFix
{
    public override string Instruction => Command.Administrator ? $"{Command.Text}, as an administrator" : Command.Text;
}

/// <summary>
/// The commands that update, uninstall or repair a package through winget, <c>dotnet tool</c> or
/// npm (docs/attack-surface.md#findings). Pure: running them is the app's, after approval. Each
/// returns <c>null</c> when the id or a version isn't plain, so nothing built from the machine can
/// add an argument or reach a shell.
/// </summary>
public static partial class Packages
{
    /// <summary>The managers a global tool can be updated and uninstalled with.</summary>
    public static bool Manages(string manager) => manager is "dotnet" or "npm";

    /// <summary>
    /// Update a global tool to the newest version, which the manager finds when the user asks. Neither is
    /// asked beforehand: <c>npm outdated</c> would send every global package's name to the registry
    /// unattended, and online lookups are opt-in (docs/attack-surface.md).
    /// </summary>
    public static PackageFix? Update(GlobalTool tool) => tool.Manager switch
    {
        "dotnet" when Plain(tool.Id) => new(PackageChange.Update, tool.Id, new("dotnet", ["tool", "update", "--global", tool.Id])),
        "npm" when NpmName(tool.Id) => new(PackageChange.Update, tool.Id, new("npm", ["install", "--global", $"{tool.Id}@latest"])),
        _ => null,
    };

    public static PackageFix? Uninstall(GlobalTool tool) => tool.Manager switch
    {
        "dotnet" when Plain(tool.Id) => new(PackageChange.Uninstall, tool.Id, new("dotnet", ["tool", "uninstall", "--global", tool.Id])),
        "npm" when NpmName(tool.Id) => new(PackageChange.Uninstall, tool.Id, new("npm", ["uninstall", "--global", tool.Id])),
        _ => null,
    };

    /// <summary>Update a program to the version winget offers; <c>null</c> when it offers none.</summary>
    /// <param name="machine">Installed for everyone (<see cref="UninstallEntry.Machine"/>): an administrator's change.</param>
    public static PackageFix? Update(WingetPackage package, bool machine) =>
        Plain(package.Id) && package.Available is { } available && IsVersion(available)
            ? new(PackageChange.Update, package.Name, new("winget", ["upgrade", "--id", package.Id, "--exact", "--version", available], machine))
            : null;

    public static PackageFix? Uninstall(WingetPackage package, bool machine) =>
        Plain(package.Id)
            ? new(PackageChange.Uninstall, package.Name, new("winget", ["uninstall", "--id", package.Id, "--exact"], machine))
            : null;

    /// <summary>
    /// Reinstall the installed version over itself: without <c>--version</c> winget would install the latest.
    /// <c>null</c> without a plain version.
    /// </summary>
    public static PackageFix? Repair(WingetPackage package, bool machine) =>
        Plain(package.Id) && package.Version is { } version && IsVersion(version)
            ? new(PackageChange.Repair, package.Name, new("winget", ["install", "--id", package.Id, "--exact", "--version", version, "--force"], machine))
            : null;

    /// <summary>
    /// The winget package an uninstall entry is, by name and version; <c>null</c> when none or more
    /// than one fits, since a wrong match would change another program.
    /// </summary>
    public static WingetPackage? Of(UninstallEntry entry, IEnumerable<WingetPackage> packages)
    {
        WingetPackage[] matches = [.. packages.Where(p => string.Equals(p.Name, entry.Name, StringComparison.OrdinalIgnoreCase)
            && (p.Version is null || entry.Version is null || string.Equals(p.Version, entry.Version, StringComparison.OrdinalIgnoreCase)))];
        return matches is [var only] ? only : null;
    }

    /// <summary>The command that lists what winget installed and what it would update.</summary>
    public static readonly (string Manager, string[] Arguments) WingetListing = ("winget", ["list", "--source", "winget", "--disable-interactivity"]);

    /// <summary>
    /// The rows of <c>winget list</c>'s table: Name, Id, Version and, when anything has one, Available.
    /// Columns are where the header's words start; a row whose cells don't start after a space there
    /// (a name with wide characters shifts them) is left out rather than read wrong. Only the first
    /// table: winget prints a second for packages that need explicit targeting.
    /// </summary>
    public static IReadOnlyList<WingetPackage> WingetList(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return [];
        var lines = output.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').Select(l => l[(l.LastIndexOf('\r', StringComparison.Ordinal) + 1)..]).ToArray();
        var rule = Array.FindIndex(lines, l => l.Length >= 10 && l.All(c => c == '-'));
        if (rule < 1)
            return [];
        var header = lines[rule - 1];
        int[] starts = [.. Enumerable.Range(0, header.Length).Where(i => header[i] != ' ' && (i == 0 || header[i - 1] == ' '))];
        if (starts.Length is not (3 or 4) || starts[0] != 0)
            return [];
        List<WingetPackage> packages = [];
        foreach (var line in lines.Skip(rule + 1).TakeWhile(l => l.Trim().Length > 0))
        {
            if (Cells(line, starts) is not [var name, var id, var version, .. var rest] || name.Length == 0 || id.Length == 0)
                continue;
            // A version winget can't read shows as "< 1.0" or "Unknown": no version, so no command is built from it.
            packages.Add(new(name, id, IsVersion(version) ? version : null, rest is [var available] && IsVersion(available) ? available : null));
        }
        return packages;
    }

    /// <summary>The cells of a fixed-width row; <c>null</c> when a cell doesn't start where its column does.</summary>
    static string[]? Cells(string line, int[] starts)
    {
        var cells = new string[starts.Length];
        for (var i = 0; i < starts.Length; i++)
        {
            var start = starts[i];
            if (start > line.Length)
            {
                cells[i] = "";
                continue;
            }
            if (start > 0 && line[start - 1] != ' ')
                return null;
            var end = i + 1 < starts.Length ? Math.Min(starts[i + 1], line.Length) : line.Length;
            cells[i] = line[start..end].Trim();
        }
        return cells[1].Contains(' ', StringComparison.Ordinal) ? null : cells;
    }

    /// <summary>A package id or version and nothing else: no space, quote, or shell character.</summary>
    static bool Plain(string value) => Token().IsMatch(value);

    /// <summary>A version number: plain, and starting with a digit, so not winget's "Unknown".</summary>
    static bool IsVersion(string value) => Plain(value) && char.IsAsciiDigit(value[0]);

    /// <summary>An npm package name, scoped or not, as the registry allows them.</summary>
    static bool NpmName(string value) => Npm().IsMatch(value);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._+-]*$")]
    private static partial Regex Token();

    [GeneratedRegex(@"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")]
    private static partial Regex Npm();
}
