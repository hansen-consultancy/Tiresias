using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>A program that extensions run inside, such as VS Code: how it is named, its executable's file name, and its command-line tool.</summary>
public sealed record ExtensionHost(string Name, string Executable, string Cli);

/// <summary>An extension installed for the user, from its host's own metadata. Never its files or settings.</summary>
/// <param name="Publisher">The marketplace publisher, or <c>null</c> when unknown: installed from a file, or without a publisher id.</param>
/// <param name="Updated">When it was installed or last updated on this machine, or <c>null</c> when not recorded.</param>
/// <param name="PublisherId">The marketplace's id for <paramref name="Publisher"/>, which trust is given to; <c>null</c> when not recorded.</param>
public sealed record InstalledExtension(ExtensionHost Host, string Id, string? Version, string? Publisher, DateTimeOffset? Updated, string? PublisherId = null);

/// <summary>A program Windows starts at log-on.</summary>
/// <param name="Where">Where the entry is: <c>Run key</c>, <c>machine Run key</c>, <c>Startup folder</c> or <c>scheduled task</c>.</param>
/// <param name="Path">The executable it starts, or <c>null</c> when it couldn't be resolved.</param>
/// <param name="Signed">Whether the file has a valid Authenticode signature; <c>null</c> when it couldn't be checked.</param>
/// <param name="Item">What Windows calls the entry to turn it off: the Run value's name, or the Startup folder file's name; <c>null</c> for a scheduled task.</param>
/// <param name="InTray">Whether the program has an icon in the notification area: used from there, which Windows doesn't record, so its last use is unknown.</param>
/// <param name="On">Whether it starts: <c>false</c> once turned off in Task Manager or Settings, or for a disabled task.</param>
/// <param name="BuiltByYou">It has no signature and looks like the user's own build (<see cref="OwnBuild.Looks"/>).</param>
/// <param name="Signer">Who signed it, when <paramref name="Signed"/> is <c>true</c>.</param>
public sealed record StartupEntry(string Name, string Where, string? Path, bool? Signed, string? Item = null, bool InTray = false, bool On = true,
    bool BuiltByYou = false, Publisher? Signer = null)
{
    public const string RunKey = "Run key";
    public const string MachineRunKey = "machine Run key";
    public const string StartupFolder = "Startup folder";
    public const string ScheduledTask = "scheduled task";
}

/// <summary>When a program last ran for the user, as Windows records it.</summary>
/// <param name="Opened">The user started it themselves, from Explorer, the Start menu or the taskbar (UserAssist); otherwise it ran some other way too, at log-on, from a script or a service (the admin tier's <c>lastrun</c>).</param>
public sealed record ProgramRun(string Path, DateTimeOffset LastRun, bool Opened = true);

/// <summary>
/// Turn off a log-on entry the way Task Manager and Settings do, keeping the program: Settings,
/// Apps, Startup turns it back on. The app does it for the user's own entries; a machine-wide one
/// needs an administrator, so it opens that page.
/// </summary>
public sealed record DisableStartup(string Name, string Where, string Item) : DoctorFix
{
    /// <summary>Where Task Manager and Settings record a log-on entry turned off, under <c>Run</c> or <c>StartupFolder</c>.</summary>
    public const string ApprovedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\";

    public bool Machine => Where == StartupEntry.MachineRunKey;

    public override string Instruction => $"turn off {Name} in Settings, Apps, Startup{(Machine ? " (needs an administrator)" : "")}";

    /// <summary>Whether <paramref name="item"/> names one value and nothing else: it comes from the registry or a folder any program can write.</summary>
    public static bool IsSafeItem(string item) => item.Length is > 0 and < 260 && item.IndexOfAny(['\\', '/', '\0']) < 0;
}

/// <summary>Look over what starts at log-on: the app's Startup list, which also turns entries off.</summary>
public sealed record ReviewStartup : DoctorFix
{
    public override string Instruction => "review it in Tiresias, Startup, or in Settings, Apps, Startup";
}

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
    public const string OwnBuildStartupKind = "programs you built yourself that start at log-on";
    public const string BlockedKind = "blocked programs still on this PC";
    public const string IdleStartupKind = "programs that start at log-on but you haven't opened in 90 days";

    /// <summary>The reason a program not opened in 90 days is flagged for; trust in its signer hides it.</summary>
    public const string UnusedReason = "unused";

    /// <summary>
    /// Guided setup phase 5's first slice (docs/attack-surface.md): installed code that can reach a
    /// credential and has a reason to be doubted. Each finding has a fix and no position, since
    /// removing code changes who can reach a credential, not how it is held. Blocked programs come
    /// first, then extensions by how many services their host reached, then unsigned startup entries,
    /// then log-on entries for programs the user hasn't opened in 90 days.
    /// </summary>
    /// <param name="blocked">Programs on the "This wasn't me" blocklist whose file is still there.</param>
    /// <param name="runs">When the user last started each program; a program missing here has an unknown last use, never "unused".</param>
    public static IEnumerable<DoctorCheck> AttackSurface(IEnumerable<InstalledExtension> extensions, IEnumerable<StartupEntry> startup,
        IEnumerable<CredentialUse> uses, IEnumerable<string> blocked, DateTimeOffset now, IEnumerable<ProgramRun>? runs = null)
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
                new RemoveExtension(extension.Host, extension.Id), Kind: ExtensionKind)
            {
                Item = $"extension {extension.Host.Executable} {extension.Id}".ToLowerInvariant(),
                Reasons = reasons,
                Signer = extension.Publisher is null ? null : Publisher.Marketplace(extension.PublisherId, extension.Publisher),
                TrustHides = true,
            };

        foreach (var entry in startupEntries.Where(e => e is { Signed: false, Path: not null } && !blockedPaths.Any(b => SamePath(b, e.Path))))
        {
            var reached = recent.Where(u => SamePath(u.Program, entry.Path)).Select(u => u.Service).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var used = reached.Length > 0 ? $"; it used {string.Join(", ", reached)} through Tiresias in the last 90 days" : "";
            DoctorCheck unsigned = new($"{entry.Name} starts at log-on unsigned", DoctorStatus.Warn,
                $"{entry.Path}, from the {entry.Where}, has no valid signature, so nothing says who made it{used}. Check where it came from",
                new RevealFile(entry.Path!), Kind: UnsignedStartupKind);
            // A developer's own tool started from its build folder: information kept in view, not a warning to dismiss at every rebuild.
            yield return entry.BuiltByYou
                ? new DoctorCheck($"{entry.Name} starts at log-on, built by you", DoctorStatus.Ok,
                    $"{entry.Path}, from the {entry.Where}, has no signature, but it sits in a git work tree beside the project that builds it, "
                    + $"so it looks like your own build{used}",
                    new ReviewStartup(), Kind: OwnBuildStartupKind) { WithoutDeveloperTools = unsigned }
                : unsigned;
        }

        // Only what the user opened: a program started at log-on runs at every log-on.
        var lastRuns = (runs ?? []).Where(r => r.Opened).GroupBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Max(r => r.LastRun), StringComparer.OrdinalIgnoreCase);
        // Tiresias's own entry is left alone: a tray app is used without being opened again, and it is what is asking.
        foreach (var entry in startupEntries.Where(e => e is { Path: not null, Item: not null, InTray: false } && DisableStartup.IsSafeItem(e.Item)
                     && !(e.Where == StartupEntry.RunKey && e.Item == "Tiresias") && !blockedPaths.Any(b => SamePath(b, e.Path))))
        {
            if (!lastRuns.TryGetValue(entry.Path!, out var lastRun) || now - lastRun <= ReachWindow || recent.Any(u => SamePath(u.Program, entry.Path)))
                continue;
            yield return new($"{entry.Name} starts at log-on, unused", DoctorStatus.Warn,
                $"Windows starts {entry.Path} at every log-on, from the {entry.Where}, but you last opened it yourself on {lastRun:yyyy-MM-dd}. "
                + "Turn it off at log-on; the program stays installed and you can still open it when you need it",
                new DisableStartup(entry.Name, entry.Where, entry.Item!), Kind: IdleStartupKind)
            {
                Item = $"startup {entry.Where} {entry.Item}".ToLowerInvariant(),
                Reasons = [UnusedReason],
                Signer = entry.Signed == true ? entry.Signer : null,
                TrustHides = true,
            };
        }
    }

    /// <summary>Whether a <c>StartupApproved</c> value says the entry is turned off: Task Manager and Settings set the first byte odd.</summary>
    public static bool StartupTurnedOff(byte[]? approved) => approved is { Length: > 0 } && (approved[0] & 1) == 1;

    /// <summary>
    /// The programs in a UserAssist <c>Count</c> key: value names are ROT13 paths, some starting with
    /// a known folder's id, which <paramref name="knownFolder"/> resolves; the data holds the last run
    /// as a FILETIME at byte 60. Shortcuts, entries never run and unresolved folders are skipped.
    /// </summary>
    public static IEnumerable<ProgramRun> UserAssistRuns(IEnumerable<(string Name, byte[]? Data)> values, Func<Guid, string?> knownFolder)
    {
        foreach (var (name, data) in values)
        {
            if (data is not { Length: >= 68 })
                continue;
            var path = Rot13(name);
            if (path.StartsWith('{', StringComparison.Ordinal) && path.IndexOf('}', StringComparison.Ordinal) is > 0 and var close)
            {
                if (!Guid.TryParse(path[..(close + 1)], out var folder) || knownFolder(folder) is not { } resolved)
                    continue;
                path = resolved.TrimEnd('\\') + path[(close + 1)..];
            }
            if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.Length < 4 || path[1] != ':')
                continue;
            var fileTime = BitConverter.ToInt64(data, 60);
            if (fileTime <= 0 || fileTime >= DateTime.MaxValue.ToFileTimeUtc())
                continue;
            yield return new(path, DateTimeOffset.FromFileTime(fileTime).ToUniversalTime());
        }
    }

    static string Rot13(string text) => string.Create(text.Length, text, (span, source) =>
    {
        for (var i = 0; i < source.Length; i++)
            span[i] = source[i] switch
            {
                >= 'a' and <= 'z' and var c => (char)('a' + (c - 'a' + 13) % 26),
                >= 'A' and <= 'Z' and var c => (char)('A' + (c - 'A' + 13) % 26),
                var c => c,
            };
    });

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
                string? publisherId = null;
                if (item.TryGetProperty("metadata", out var metadata) && metadata.ValueKind == JsonValueKind.Object)
                {
                    publisherId = Text(metadata, "publisherId");
                    publisher = Text(metadata, "source") == "vsix" || Text(metadata, "publisherId") is not { Length: > 0 }
                        ? null
                        : Text(metadata, "publisherDisplayName") ?? publisher;
                    if (metadata.TryGetProperty("installedTimestamp", out var stamp) && stamp.TryGetInt64(out var ms)
                        && ms >= 0 && ms <= DateTimeOffset.MaxValue.ToUnixTimeMilliseconds())
                        updated = DateTimeOffset.FromUnixTimeMilliseconds(ms);
                }
                found.Add(new(host, id, Text(item, "version"), publisher, updated, publisher is null ? null : publisherId));
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
