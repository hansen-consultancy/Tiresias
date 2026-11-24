namespace Tiresias.Client;

/// <summary>A log-on entry with what is known of it (docs/attack-surface.md, <b>Startup</b>).</summary>
/// <param name="App">The installed app whose folder holds its program; <c>null</c> when it isn't from an installed app.</param>
/// <param name="LastOpened">When the user last opened its program themselves; <c>null</c> when not recorded.</param>
/// <param name="Reached">The services its program used through Tiresias in the last 90 days.</param>
public sealed record StartupProgram(StartupEntry Entry, string? App, DateTimeOffset? LastOpened, IReadOnlyList<string> Reached);

public static partial class Doctor
{
    /// <summary>
    /// Every log-on entry once per place and name, with the installed app it belongs to (the deepest
    /// app folder holding its program), its last opening and its credential use. Entries not from an
    /// installed app come first, the interesting case, then by name.
    /// </summary>
    public static IReadOnlyList<StartupProgram> StartupPrograms(IEnumerable<StartupEntry> startup, IEnumerable<UninstallEntry> installed,
        IEnumerable<ProgramRun> runs, IEnumerable<CredentialUse> uses, DateTimeOffset now)
    {
        var apps = installed.Where(e => e.Folder is { } folder && Deep(folder)).OrderByDescending(e => e.Folder!.Length).ToArray();
        var opened = runs.Where(r => r.Opened).ToArray();
        var recent = uses.Where(u => now - u.At <= ReachWindow).ToArray();
        return [.. startup.DistinctBy(e => (e.Where, e.Name.ToUpperInvariant(), e.Path?.ToUpperInvariant())).Select(entry =>
            {
                var path = entry.Path;
                return new StartupProgram(entry,
                    path is null ? null : apps.FirstOrDefault(a => IsUnder(path, a.Folder!))?.Name,
                    opened.Where(r => SamePath(r.Path, path)).Select(r => (DateTimeOffset?)r.LastRun).Max(),
                    [.. recent.Where(u => SamePath(u.Program, path)).Select(u => u.Service).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)]);
            })
            .OrderBy(p => p.App is null ? 0 : 1).ThenBy(p => p.Entry.Name, StringComparer.OrdinalIgnoreCase)];
    }
}
