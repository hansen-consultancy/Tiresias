using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>A developer tool installed for every project: its package manager, its package id and version.</summary>
/// <param name="Manager"><c>dotnet</c>, <c>npm</c>, <c>pipx</c> or <c>cargo</c>.</param>
/// <param name="Latest">A newer version its manager's registry names; <c>null</c> when none or not asked (only npm says).</param>
public sealed record GlobalTool(string Manager, string Id, string? Version, string? Latest = null);

/// <summary>
/// The global tools and winget's programs as last listed and when. Listing them takes seconds, so the
/// agent keeps one listing a day on disk (<c>inventory.json</c> beside the keyring) instead of one per
/// doctor run. Package names, ids and versions only: no paths, no user names.
/// </summary>
/// <param name="Winget">What <c>winget list --source winget</c> listed; <c>null</c> reads as none.</param>
public sealed record ToolSnapshot(DateTimeOffset At, IReadOnlyList<GlobalTool> Tools, IReadOnlyList<WingetPackage>? Winget = null)
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 2;

    /// <summary>winget's programs, by name and version, which the uninstall entries are matched against (<see cref="Packages.Of"/>).</summary>
    public IReadOnlyList<WingetPackage> WingetPackages => Winget ?? [];

    /// <summary>How old a listing may be before it is taken again.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(1);

    /// <summary>Whether to list again: no listing, one a day old, or one from the future (a clock set back).</summary>
    public static bool IsDue(ToolSnapshot? snapshot, DateTimeOffset now) =>
        snapshot is not { At: var at } || now - at >= MaxAge || at > now;

    public string ToJson() => JsonSerializer.Serialize(new
    {
        version = Version,
        at = At,
        tools = Tools.Select(t => new { manager = t.Manager, id = t.Id, version = t.Version, latest = t.Latest }),
        winget = WingetPackages.Select(p => new { name = p.Name, id = p.Id, version = p.Version, available = p.Available }),
    });

    /// <summary>The listing in <paramref name="json"/>; <c>null</c> when it is missing, damaged or another version, so it is taken again.</summary>
    public static ToolSnapshot? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number || version.GetInt32() != Version
                || !root.TryGetProperty("at", out var at) || at.ValueKind != JsonValueKind.String || !at.TryGetDateTimeOffset(out var taken)
                || !root.TryGetProperty("tools", out var tools) || tools.ValueKind != JsonValueKind.Array)
                return null;
            List<GlobalTool> list = [];
            foreach (var tool in tools.EnumerateArray())
            {
                if (tool.ValueKind != JsonValueKind.Object || Doctor.Text(tool, "manager") is not { } manager || Doctor.Text(tool, "id") is not { } id)
                    return null;
                list.Add(new(manager, id, Doctor.Text(tool, "version"), Doctor.Text(tool, "latest")));
            }
            List<WingetPackage> winget = [];
            if (root.TryGetProperty("winget", out var packages) && packages.ValueKind == JsonValueKind.Array)
                foreach (var package in packages.EnumerateArray())
                {
                    if (package.ValueKind != JsonValueKind.Object || Doctor.Text(package, "name") is not { } name || Doctor.Text(package, "id") is not { } packageId)
                        return null;
                    winget.Add(new(name, packageId, Doctor.Text(package, "version"), Doctor.Text(package, "available")));
                }
            return new(taken, list, winget);
        }
        catch (Exception e) when (e is JsonException or FormatException)
        {
            return null;
        }
    }
}

/// <summary>What <c>tir doctor --surface</c> lists: the inventory behind the attack surface findings, without judging it.</summary>
public sealed record SurfaceInventory(
    IReadOnlyList<InstalledExtension> Extensions,
    ToolSnapshot Tools,
    IReadOnlyList<StartupEntry> Startup,
    IReadOnlyList<CredentialUse> Uses,
    IReadOnlyList<ProgramRun> Runs);

public static partial class Doctor
{
    /// <summary>The package managers asked for global tools, each with the arguments that list them.</summary>
    public static readonly IReadOnlyList<(string Manager, string[] Arguments)> ToolManagers =
    [
        ("dotnet", ["tool", "list", "--global"]),
        ("npm", ["ls", "--global", "--json", "--depth=0"]),
        ("pipx", ["list", "--json"]),
        ("cargo", ["install", "--list"]),
    ];

    /// <summary>
    /// The global tools in a package manager's own listing (<see cref="ToolManagers"/>); none when
    /// the output is missing or not what that manager prints.
    /// </summary>
    public static IReadOnlyList<GlobalTool> GlobalTools(string manager, string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return [];
        return manager switch
        {
            "dotnet" => [.. output.Split('\n').Skip(2).Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .Where(p => p.Length >= 2).Select(p => new GlobalTool(manager, p[0], p[1]))],
            "cargo" => [.. CargoLine().Matches(output).Select(m => new GlobalTool(manager, m.Groups[1].Value, m.Groups[2].Value))],
            "npm" => Json(output, root => root.TryGetProperty("dependencies", out var d) && d.ValueKind == JsonValueKind.Object
                ? [.. d.EnumerateObject().Select(p => new GlobalTool(manager, p.Name, p.Value.ValueKind == JsonValueKind.Object ? Text(p.Value, "version") : null))]
                : []),
            "pipx" => Json(output, root => root.TryGetProperty("venvs", out var v) && v.ValueKind == JsonValueKind.Object
                ? [.. v.EnumerateObject().Select(p => new GlobalTool(manager, p.Name, PipxVersion(p.Value)))]
                : []),
            _ => [],
        };
    }

    static string? PipxVersion(JsonElement venv) =>
        venv.ValueKind == JsonValueKind.Object && venv.TryGetProperty("metadata", out var m) && m.ValueKind == JsonValueKind.Object
        && m.TryGetProperty("main_package", out var p) && p.ValueKind == JsonValueKind.Object ? Text(p, "package_version") : null;

    static IReadOnlyList<GlobalTool> Json(string output, Func<JsonElement, IReadOnlyList<GlobalTool>> read)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            return document.RootElement.ValueKind == JsonValueKind.Object ? read(document.RootElement) : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    [GeneratedRegex(@"^(\S+) v(\S+?):?\s*$", RegexOptions.Multiline)]
    private static partial Regex CargoLine();

    /// <summary>
    /// The inventory as <c>tir doctor --surface</c> prints it: each extension host with what it reached
    /// through Tiresias in the last 90 days and its extensions, the global tools, and what starts at
    /// log-on with its signature and last use. What Windows doesn't record is "unknown", never guessed.
    /// </summary>
    public static IEnumerable<string> InventoryLines(SurfaceInventory inventory, DateTimeOffset now)
    {
        var recent = inventory.Uses.Where(u => now - u.At <= ReachWindow).ToArray();
        yield return "Extensions";
        if (inventory.Extensions.Count == 0)
            yield return "  none found";
        foreach (var host in inventory.Extensions.GroupBy(e => e.Host).OrderBy(g => g.Key.Name, StringComparer.OrdinalIgnoreCase))
        {
            var reached = recent.Where(u => string.Equals(FileName(u.Program), host.Key.Executable, StringComparison.OrdinalIgnoreCase))
                .Select(u => u.Service).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            yield return $"  {host.Key.Name} ({host.Count()}): {(reached.Length > 0 ? $"reached {string.Join(", ", reached)}" : "reached nothing")} in 90 days";
            foreach (var extension in host.OrderBy(e => e.Id, StringComparer.OrdinalIgnoreCase))
                yield return $"    {extension.Label} {extension.Version ?? "?"}, {extension.Publisher ?? "unknown publisher"}, "
                    + $"updated {(extension.Updated is { } updated ? updated.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "unknown")}";
        }
        yield return $"Global tools (listed {inventory.Tools.At.ToOffset(now.Offset):yyyy-MM-dd HH:mm})";
        if (inventory.Tools.Tools.Count == 0)
            yield return "  none found";
        foreach (var tool in inventory.Tools.Tools.OrderBy(t => t.Manager, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.OrdinalIgnoreCase))
            yield return $"  {tool.Manager}: {tool.Id} {tool.Version ?? "?"}{(tool.Latest is { } latest ? $", {latest} available" : "")}";
        yield return "Starts at log-on";
        if (inventory.Startup.Count == 0)
            yield return "  none found";
        var lastRuns = inventory.Runs.GroupBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Max(r => r.LastRun), StringComparer.OrdinalIgnoreCase);
        foreach (var entry in inventory.Startup.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            var signed = entry.Signed switch { true => "signed", false => "unsigned", null => "signature unchecked" };
            var used = entry.InTray ? "used from the tray" : entry.Path is not null && lastRuns.TryGetValue(entry.Path, out var run) ? $"last opened {run:yyyy-MM-dd}" : "last opened unknown";
            yield return $"  {entry.Name} ({entry.Where}): {entry.Path ?? "unresolved"}, {signed}, {used}";
        }
    }
}
