using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>
/// An uninstall registry entry: only a claim that something is installed, with what the disk says
/// about it. Read from the entry's names and paths, never by running anything.
/// </summary>
/// <param name="Key">The entry's registry key, <c>HKCU\…\Uninstall\&lt;name&gt;</c> or <c>HKLM\…</c>.</param>
/// <param name="Uninstaller">The program its <c>UninstallString</c> starts; <c>null</c> for Windows Installer entries and
/// commands that don't name a full path, which say nothing about the disk.</param>
/// <param name="UninstallerExists">Whether <paramref name="Uninstaller"/> is on disk.</param>
/// <param name="FolderExists">Whether its <c>InstallLocation</c>, or the uninstaller's folder when it names none, is on disk.</param>
/// <param name="Command">Its whole <c>UninstallString</c>, what the Uninstall button runs.</param>
public sealed record UninstallEntry(string Key, string Name, string? Version, string? Uninstaller, bool UninstallerExists, bool FolderExists, string? Command = null)
{
    /// <summary>A machine-wide entry, which only an administrator can change.</summary>
    public bool Machine => Key.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Delete an uninstall entry that no longer matches what is on disk, after saving it to a
/// <c>.reg</c> file that puts it back. The app does it for the user's own entries; a machine-wide
/// one needs an administrator, so it gets the commands.
/// </summary>
public sealed partial record RemoveEntry(string Key, string Name) : DoctorFix
{
    public bool Machine => Key.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase);

    public override string Instruction =>
        $"reg export \"{Key}\" \"{BackupName}\", then reg delete \"{Key}\" /f{(Machine ? ", as an administrator" : "")}";

    /// <summary>The backup's file name: the key's last part, without what a file name can't hold.</summary>
    public string BackupName => $"{Unsafe().Replace(Key[(Key.LastIndexOf('\\') + 1)..], "_")}.reg";

    /// <summary>
    /// Whether <paramref name="key"/> is a subkey of an Uninstall key and nothing else, so it can be
    /// deleted: the name comes from the registry, which any installer can write.
    /// </summary>
    public static bool IsSafeKey(string key) => SafeKey().IsMatch(key);

    [GeneratedRegex(@"^HK(CU|LM)\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\""\r\n\0]+$", RegexOptions.IgnoreCase)]
    private static partial Regex SafeKey();

    [GeneratedRegex(@"[^A-Za-z0-9._ {}-]")]
    private static partial Regex Unsafe();
}

/// <summary>
/// Reinstall the installed version over itself, which restores a missing uninstaller. With the
/// winget id it is winget's own command; without one, the steps.
/// </summary>
public sealed record Repair(string Name, string? Version, string? WingetId = null) : DoctorFix
{
    public override string Instruction => WingetId is not null
        ? $"winget install --id {WingetId} --exact{(Version is null ? "" : $" --version {Version}")} --force"
        : $"reinstall {Name}{(Version is null ? "" : $" {Version}")} over itself with its own installer; that restores its uninstaller";
}

public static partial class Doctor
{
    public const string GoneEntryKind = "uninstall entries for software that is gone";
    public const string NoUninstallerKind = "programs that can't be uninstalled";
    public const string StaleEntryKind = "stale uninstall entries";

    /// <summary>
    /// Uninstall entries checked against the disk (docs/attack-surface.md): an entry whose uninstaller
    /// and folder are both gone, a program present without its uninstaller, and an older version's
    /// entry with the same uninstall command as a newer one. The whole command, not the program it
    /// starts: shared uninstallers (an installer engine, <c>rundll32</c>) serve many products, each
    /// with its own arguments. Entries that say nothing about the disk (Windows Installer, no full
    /// path) raise nothing.
    /// </summary>
    public static IEnumerable<DoctorCheck> UninstallEntries(IEnumerable<UninstallEntry> entries)
    {
        var all = entries.Where(e => e.Uninstaller is not null).ToArray();
        foreach (var entry in all.Where(e => !e.UninstallerExists).OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
            yield return entry.FolderExists
                ? new($"{Label(entry)} can't be uninstalled", DoctorStatus.Warn,
                    $"Its uninstaller {entry.Uninstaller} is gone, but the program is still there. Reinstall the same version over it to restore the uninstaller; "
                    + "removing it by hand leaves its shell extensions and services registered",
                    new Repair(entry.Name, entry.Version), Kind: NoUninstallerKind)
                : new($"{Label(entry)} is listed but gone", DoctorStatus.Warn,
                    $"Windows lists it as installed, but neither its uninstaller {entry.Uninstaller} nor its folder exists. "
                    + "Remove the entry; any data folders it left are yours to check"
                    + (entry.Machine ? ". It is machine-wide, so this needs an administrator" : ""),
                    new RemoveEntry(entry.Key, entry.Name), Kind: GoneEntryKind);

        var shared = all.Where(e => e is { UninstallerExists: true, Command.Length: > 0 })
            .GroupBy(e => e.Command!.Trim(), StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1);
        foreach (var group in shared)
        {
            var versions = group.Select(e => (Entry: e, Version: ParseVersion(e.Version))).ToArray();
            if (versions.Any(v => v.Version is null))
                continue;
            var newest = versions.Max(v => v.Version)!;
            var current = versions.First(v => v.Version == newest).Entry;
            foreach (var (stale, _) in versions.Where(v => v.Version < newest).OrderBy(v => v.Version))
                yield return new($"{Label(stale)} is a stale entry for {Label(current)}", DoctorStatus.Warn,
                    $"Both run {current.Uninstaller}, the uninstaller of version {current.Version}. Don't use Uninstall on the old entry: "
                    + "it removes the current program's files, and the program fails the next time it starts. Remove the entry instead"
                    + (stale.Machine ? ". It is machine-wide, so this needs an administrator" : ""),
                    new RemoveEntry(stale.Key, stale.Name), Kind: StaleEntryKind);
        }
    }

    /// <summary>The entry's name with its version, unless the name already says it.</summary>
    static string Label(UninstallEntry entry) =>
        entry.Version is { Length: > 0 } version && !entry.Name.Contains(version, StringComparison.OrdinalIgnoreCase) ? $"{entry.Name} {version}" : entry.Name;

    /// <summary>A display version's leading numbers, <c>1.2.3</c> of <c>1.2.3-beta</c>; <c>null</c> when it has none to compare.</summary>
    static Version? ParseVersion(string? version)
    {
        if (version is null || LeadingVersion().Match(version) is not { Success: true } match)
            return null;
        var text = match.Value.Contains('.', StringComparison.Ordinal) ? match.Value : match.Value + ".0";
        return System.Version.TryParse(text, out var parsed) ? parsed : null;
    }

    [GeneratedRegex(@"^\d+(\.\d+){0,3}")]
    private static partial Regex LeadingVersion();
}
