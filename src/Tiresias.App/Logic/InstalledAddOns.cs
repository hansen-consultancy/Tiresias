using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>An extension or a global tool, as a row of the Installed page's Extensions and Global tools views.</summary>
/// <param name="In">The program it runs inside (an extension's host), or the package manager that installed a tool.</param>
/// <param name="Reached">What its host used through Tiresias in the last 90 days, sorted; empty for a tool, whose use isn't recorded.</param>
/// <param name="Tool">The global tool it is, which its manager can update and uninstall and the online lookups ask about; <c>null</c> for an extension.</param>
public sealed record AddOn(string Name, string? Version, string In, string? Publisher, DateTimeOffset? Updated, IReadOnlyList<string> Reached, GlobalTool? Tool = null);

/// <summary>What the Installed page lists beside programs (#107): read-only, no findings of its own.</summary>
public static class InstalledAddOns
{
    /// <summary>
    /// Every extension with what its host reached in 90 days: an extension can use whatever its host
    /// gets. Those whose host reached most come first, then by host and name.
    /// </summary>
    public static IReadOnlyList<AddOn> Extensions(IEnumerable<InstalledExtension> extensions, IEnumerable<CredentialUse> uses, DateTimeOffset now)
    {
        var reached = uses.Where(u => now - u.At <= Doctor.ReachWindow)
            .GroupBy(u => FileName(u.Program), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)[.. g.Select(u => u.Service).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)],
                StringComparer.OrdinalIgnoreCase);
        return [.. extensions
            .Select(e => new AddOn(e.Label, e.Version, e.Host.Name, e.Publisher, e.Updated, reached.GetValueOrDefault(e.Host.Executable) ?? []))
            .OrderByDescending(a => a.Reached.Count).ThenBy(a => a.In, StringComparer.OrdinalIgnoreCase).ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>The global tools of the day's listing, by manager and id; their publisher and use aren't known offline.</summary>
    public static IReadOnlyList<AddOn> Tools(ToolSnapshot snapshot) =>
        [.. snapshot.Tools.OrderBy(t => t.Manager, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.OrdinalIgnoreCase)
            .Select(t => new AddOn(t.Id, t.Version, t.Manager, null, null, [], t))];

    /// <summary>Every word typed must appear, in any case, in its name, version, host or manager, publisher or a service reached.</summary>
    public static IEnumerable<AddOn> Filter(IEnumerable<AddOn> addOns, string search)
    {
        var words = search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return addOns.Where(a => words.All(w => ((string[])[a.Name, a.Version ?? "", a.In, a.Publisher ?? "", .. a.Reached])
            .Any(h => h.Contains(w, StringComparison.OrdinalIgnoreCase))));
    }

    /// <summary>The file name in a Windows path, on any OS: the logs write Windows paths.</summary>
    static string FileName(string path) => path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
}
