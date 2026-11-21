using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>A developer tool installed for every project: its package manager, its package id and version.</summary>
/// <param name="Manager"><c>dotnet</c>, <c>npm</c>, <c>pipx</c> or <c>cargo</c>.</param>
public sealed record GlobalTool(string Manager, string Id, string? Version);

/// <summary>What <c>tir doctor --surface</c> lists: the inventory behind the attack surface findings, without judging it.</summary>
public sealed record SurfaceInventory(
    IReadOnlyList<InstalledExtension> Extensions,
    IReadOnlyList<GlobalTool> Tools,
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
                yield return $"    {extension.Id} {extension.Version ?? "?"}, {extension.Publisher ?? "unknown publisher"}, "
                    + $"updated {(extension.Updated is { } updated ? updated.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "unknown")}";
        }
        yield return "Global tools";
        if (inventory.Tools.Count == 0)
            yield return "  none found";
        foreach (var tool in inventory.Tools.OrderBy(t => t.Manager, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.OrdinalIgnoreCase))
            yield return $"  {tool.Manager}: {tool.Id} {tool.Version ?? "?"}";
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
