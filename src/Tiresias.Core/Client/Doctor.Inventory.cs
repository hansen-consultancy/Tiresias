using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>A developer tool installed for every project: its package manager, its package id and version.</summary>
/// <param name="Manager"><c>dotnet</c>, <c>npm</c>, <c>pipx</c> or <c>cargo</c>.</param>
public sealed record GlobalTool(string Manager, string Id, string? Version);

/// <summary>
/// The global tools as last listed and when. Listing them takes seconds, so the agent keeps one
/// listing a day on disk (<c>inventory.json</c> beside the keyring) instead of one per doctor run.
/// Package names and versions only: no paths, no user names.
/// </summary>
public sealed record ToolSnapshot(DateTimeOffset At, IReadOnlyList<GlobalTool> Tools)
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 1;

    /// <summary>How old a listing may be before it is taken again.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(1);

    /// <summary>Whether to list again: no listing, one a day old, or one from the future (a clock set back).</summary>
    public static bool IsDue(ToolSnapshot? snapshot, DateTimeOffset now) =>
        snapshot is not { At: var at } || now - at >= MaxAge || at > now;

    public string ToJson() => JsonSerializer.Serialize(new
    {
        version = Version,
        at = At,
        tools = Tools.Select(t => new { manager = t.Manager, id = t.Id, version = t.Version }),
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
                list.Add(new(manager, id, Doctor.Text(tool, "version")));
            }
            return new(taken, list);
        }
        catch (Exception e) when (e is JsonException or FormatException)
        {
            return null;
        }
    }
}

/// <summary>What <c>tir doctor --surface</c> lists: the inventory behind the attack surface findings, without judging it.</summary>
/// <param name="Lookups">The opt-in online lookups' answers; <c>null</c> while they are off.</param>
public sealed record SurfaceInventory(
    IReadOnlyList<InstalledExtension> Extensions,
    ToolSnapshot Tools,
    IReadOnlyList<StartupEntry> Startup,
    IReadOnlyList<CredentialUse> Uses,
    IReadOnlyList<ProgramRun> Runs,
    TrustLookups? Lookups = null);

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

    /// <summary>What the opt-in lookups said about a tool, for <c>tir doctor --surface</c>.</summary>
    static string OnlineWords(GlobalTool tool, TrustLookups? lookups) =>
        lookups is null ? "not checked online"
        : PackageQuery.Of(tool) is not { } package ? "can't be checked online"
        : lookups.For(package) switch
        {
            null => "not checked online yet",
            { Advisories.Count: 0, At: var at } => $"no known vulnerability ({OsvSource}, {at:yyyy-MM-dd})",
            { Advisories: var advisories, At: var at } => $"known vulnerabilities {string.Join(", ", advisories.Select(a => a.Id))} ({OsvSource}, {at:yyyy-MM-dd})",
        };

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
            yield return $"  {tool.Manager}: {tool.Id} {tool.Version ?? "?"}, {OnlineWords(tool, inventory.Lookups)}";
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
