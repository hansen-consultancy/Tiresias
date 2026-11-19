using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>A program that extensions run inside, such as VS Code: how it is named, its executable's file name, and its command-line tool.</summary>
public sealed record ExtensionHost(string Name, string Executable, string Cli);

/// <summary>An extension installed for the user, from its host's own metadata. Never its files or settings.</summary>
/// <param name="Publisher">The marketplace publisher, or <c>null</c> when unknown: installed from a file, or without a publisher id.</param>
/// <param name="Updated">When it was installed or last updated on this machine, or <c>null</c> when not recorded.</param>
public sealed record InstalledExtension(ExtensionHost Host, string Id, string? Version, string? Publisher, DateTimeOffset? Updated);

/// <summary>A program Windows starts at log-on.</summary>
/// <param name="Where">Where the entry is: <c>Run key</c>, <c>machine Run key</c> or <c>Startup folder</c>.</param>
/// <param name="Path">The executable it starts, or <c>null</c> when it couldn't be resolved.</param>
/// <param name="Signed">Whether the file has a valid Authenticode signature; <c>null</c> when it couldn't be checked.</param>
public sealed record StartupEntry(string Name, string Where, string? Path, bool? Signed);

/// <summary>A program that asked Tiresias for a credential and got it, from the local activity and audit logs.</summary>
/// <param name="Program">The program's image path.</param>
public sealed record CredentialUse(string Program, string Service, DateTimeOffset At);

/// <summary>Remove an extension from its host with the host's own command.</summary>
public sealed partial record RemoveExtension(ExtensionHost Host, string Id) : DoctorFix
{
    public override string Instruction => $"{Host.Cli} --uninstall-extension {Id}";

    /// <summary>
    /// Whether <paramref name="id"/> is a <c>publisher.name</c> marketplace id and nothing else, so it
    /// can be passed to the host's command: the id comes from a file any program can write.
    /// </summary>
    public static bool IsSafeId(string id) => SafeId().IsMatch(id);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_-]*\.[A-Za-z0-9][A-Za-z0-9_.-]*$")]
    private static partial Regex SafeId();
}

/// <summary>Show a file in Explorer, for the user to judge where it came from. Tiresias deletes nothing it can't attribute.</summary>
public sealed record RevealFile(string Path) : DoctorFix
{
    public override string Instruction => $"open {Path} in Explorer and check where it came from";
}

public static partial class Doctor
{
    /// <summary>How far back a host's credential use counts as reach, and how long unchanged an extension may be.</summary>
    public static readonly TimeSpan ReachWindow = TimeSpan.FromDays(90);

    public static readonly TimeSpan StaleExtension = TimeSpan.FromDays(2 * 365);

    public const string ExtensionKind = "extensions with a reason to doubt them, in programs that use credentials";
    public const string UnsignedStartupKind = "unsigned programs that start at log-on";
    public const string BlockedKind = "blocked programs still on this PC";

    /// <summary>
    /// Guided setup phase 5's first slice (docs/attack-surface.md): installed code that can reach a
    /// credential and has a reason to be doubted. Each finding has a fix and no position, since
    /// removing code changes who can reach a credential, not how it is held. Blocked programs come
    /// first, then extensions by how many services their host reached, then unsigned startup entries.
    /// </summary>
    /// <param name="blocked">Programs on the "This wasn't me" blocklist whose file is still there.</param>
    public static IEnumerable<DoctorCheck> AttackSurface(IEnumerable<InstalledExtension> extensions, IEnumerable<StartupEntry> startup,
        IEnumerable<CredentialUse> uses, IEnumerable<string> blocked, DateTimeOffset now)
    {
        var recent = uses.Where(u => now - u.At <= ReachWindow).ToArray();
        var startupEntries = startup.ToArray();
        var blockedPaths = blocked.ToArray();

        foreach (var path in blockedPaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var starts = startupEntries.Any(e => SamePath(e.Path, path));
            yield return new($"{FileName(path)} is blocked but still on this PC", DoctorStatus.Fail,
                $"You said \"This wasn't me\" about {path}, so Tiresias refuses it{(starts ? ", yet it still starts at log-on" : "")}. "
                + "Check where it came from, and remove it if no one recognises it",
                new RevealFile(path), Kind: BlockedKind);
        }

        var services = recent.GroupBy(u => FileName(u.Program), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(u => u.Service).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray(),
                StringComparer.OrdinalIgnoreCase);
        var doubted = extensions
            .Select(e => (Extension: e, Reasons: Reasons(e, now), Reach: services.GetValueOrDefault(e.Host.Executable) ?? []))
            .Where(x => x.Reasons.Count > 0 && x.Reach.Length > 0 && RemoveExtension.IsSafeId(x.Extension.Id))
            .OrderByDescending(x => x.Reach.Length).ThenBy(x => x.Extension.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var (extension, reasons, reach) in doubted)
            yield return new($"{extension.Id} in {extension.Host.Name} ({string.Join(", ", reasons)})", DoctorStatus.Warn,
                $"{extension.Host.Name} used {string.Join(", ", reach)} through Tiresias in the last 90 days, and every extension in it can use what it gets. "
                + "Remove this one if you don't need it",
                new RemoveExtension(extension.Host, extension.Id), Kind: ExtensionKind);

        foreach (var entry in startupEntries.Where(e => e is { Signed: false, Path: not null } && !blockedPaths.Any(b => SamePath(b, e.Path))))
        {
            var reached = recent.Where(u => SamePath(u.Program, entry.Path)).Select(u => u.Service).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            yield return new($"{entry.Name} starts at log-on unsigned", DoctorStatus.Warn,
                $"{entry.Path}, from the {entry.Where}, has no valid signature, so nothing says who made it"
                + (reached.Length > 0 ? $"; it used {string.Join(", ", reached)} through Tiresias in the last 90 days" : "")
                + ". Check where it came from",
                new RevealFile(entry.Path!), Kind: UnsignedStartupKind);
        }
    }

    /// <summary>Why an extension deserves doubt, in words that go into the finding's name: a new reason is a new finding.</summary>
    static List<string> Reasons(InstalledExtension extension, DateTimeOffset now)
    {
        List<string> reasons = [];
        if (extension.Publisher is null)
            reasons.Add("unknown publisher");
        if (extension.Updated is { } updated && now - updated > StaleExtension)
            reasons.Add("not updated in 2 years");
        return reasons;
    }

    /// <summary>The file name in a Windows path, on any OS: the logs and the probe write Windows paths.</summary>
    static string FileName(string path) => path[(path.LastIndexOfAny(['\\', '/']) + 1)..];

    static bool SamePath(string? a, string? b) => a is not null && b is not null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    static readonly JsonSerializerOptions LogJson = new(JsonSerializerDefaults.Web);

    static readonly HashSet<string> UseKinds = new(["Allow", "LeaseBegin", "Mint", "Token", "Elevate"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The credential uses in activity or audit log lines: which program got which service, and when.
    /// Lines that aren't records, refusals, and records without a known program are skipped. The logs
    /// hold no values, so neither does this.
    /// </summary>
    public static IEnumerable<CredentialUse> CredentialUses(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            LogLine? record;
            try
            {
                record = JsonSerializer.Deserialize<LogLine>(line, LogJson);
            }
            catch (JsonException)
            {
                continue;
            }
            if (record is not { Kind: { } kind, Process: { } process } || !UseKinds.Contains(kind) || ImagePath(process) is not { } program)
                continue;
            // An environment hand-over names the program as its service and the variables as its reason.
            var service = record.Consumer == "environment" ? "sealed environment variables" : record.Service;
            if (!string.IsNullOrEmpty(service))
                yield return new(program, service, record.Time);
        }
    }

    /// <summary>The image path in a recorded process, <c>C:\x\y.exe (pid 12)</c> or <c>C:\x\y.exe</c>; <c>null</c> when only a pid is known.</summary>
    static string? ImagePath(string process)
    {
        var path = PidSuffix().Replace(process, "").Trim();
        return path.Length == 0 || path.StartsWith("pid ", StringComparison.Ordinal) || path == "unknown image" ? null : path;
    }

    [GeneratedRegex(@"\s*\(pid \d+\)$")]
    private static partial Regex PidSuffix();

    /// <summary>
    /// The extensions in a host's <c>extensions.json</c>: id, version, publisher and install time, never
    /// anything from the extension itself. Installed from a file, or with metadata but no publisher id,
    /// is an unknown publisher; without metadata at all (older hosts) the id's prefix stands for it.
    /// </summary>
    public static IEnumerable<InstalledExtension> Extensions(ExtensionHost host, string? json)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json ?? "");
        }
        catch (JsonException)
        {
            return [];
        }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                return [];
            List<InstalledExtension> found = [];
            foreach (var item in document.RootElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object
                    || !item.TryGetProperty("identifier", out var identifier) || identifier.ValueKind != JsonValueKind.Object
                    || Text(identifier, "id") is not { Length: > 0 } id)
                    continue;
                string? publisher = id.Split('.')[0];
                DateTimeOffset? updated = null;
                if (item.TryGetProperty("metadata", out var metadata) && metadata.ValueKind == JsonValueKind.Object)
                {
                    publisher = Text(metadata, "source") == "vsix" || Text(metadata, "publisherId") is not { Length: > 0 }
                        ? null
                        : Text(metadata, "publisherDisplayName") ?? publisher;
                    if (metadata.TryGetProperty("installedTimestamp", out var stamp) && stamp.TryGetInt64(out var ms))
                        updated = DateTimeOffset.FromUnixTimeMilliseconds(ms);
                }
                found.Add(new(host, id, Text(item, "version"), publisher, updated));
            }
            return found;
        }
    }

    static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>The executable a Run-key command starts: the quoted part, or the text up to <c>.exe</c>; <c>null</c> when there is none.</summary>
    public static string? ExecutableIn(string command)
    {
        command = command.Trim();
        if (command.StartsWith("\"", StringComparison.Ordinal))
        {
            var end = command.IndexOf("\"", 1, StringComparison.Ordinal);
            return end > 1 ? command[1..end] : null;
        }
        var exe = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe > 0)
            return command[..(exe + 4)];
        var space = command.IndexOf(' ', StringComparison.Ordinal);
        return space < 0 ? (command.Length > 0 ? command : null) : command[..space];
    }

    /// <summary>The program paths on the blocklist (<c>blocklist.json</c>); none when it is missing or damaged.</summary>
    public static IReadOnlyList<string> BlockedPaths(string? json)
    {
        try
        {
            using var document = JsonDocument.Parse(json ?? "");
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("programs", out var programs) && programs.ValueKind == JsonValueKind.Array
                ? [.. programs.EnumerateArray().Where(p => p.ValueKind == JsonValueKind.Object).Select(p => Text(p, "path")).OfType<string>().Where(p => p.Length > 0)]
                : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    sealed record LogLine(DateTimeOffset Time, string? Kind, string? Consumer, string? Service, string? Process);
}
