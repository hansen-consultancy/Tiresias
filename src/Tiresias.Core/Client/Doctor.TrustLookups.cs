using System.Globalization;
using System.Text.Json;

namespace Tiresias.Client;

/// <summary>
/// All an online lookup sends about a package: its ecosystem, name and version. Never a path, a
/// user name or what asked for which credential (docs/attack-surface.md, <i>Privacy</i>).
/// </summary>
/// <param name="Ecosystem">OSV's name for the registry: <c>NuGet</c>, <c>npm</c>, <c>PyPI</c> or <c>crates.io</c>.</param>
public sealed record PackageQuery(string Ecosystem, string Name, string Version)
{
    /// <summary>What to ask about a global tool; <c>null</c> for one without a version or from a manager no source knows.</summary>
    public static PackageQuery? Of(GlobalTool tool) =>
        (EcosystemOf(tool.Manager), tool.Version) is ({ } ecosystem, { Length: > 0 } version) ? new(ecosystem, tool.Id, version) : null;

    static string? EcosystemOf(string manager) => manager switch
    {
        "dotnet" => "NuGet",
        "npm" => "npm",
        "pipx" => "PyPI",
        "cargo" => "crates.io",
        _ => null,
    };

    /// <summary>Package names are compared without case: <c>dotnet tool list</c> lowers them, the registries don't.</summary>
    public bool Matches(PackageQuery other) =>
        Ecosystem == other.Ecosystem && string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase) && Version == other.Version;
}

/// <summary>A published advisory for a package version.</summary>
/// <param name="Fixed">The first version that fixes it above the installed one; <c>null</c> when none is known.</param>
public sealed record Advisory(string Id, string? Summary, string? Fixed);

/// <summary>What a source said about one package version, and when.</summary>
public sealed record PackageVerdict(PackageQuery Package, DateTimeOffset At, IReadOnlyList<Advisory> Advisories)
{
    public bool Equals(PackageVerdict? other) => other is not null && Package == other.Package && At == other.At && Advisories.SequenceEqual(other.Advisories);

    public override int GetHashCode() => HashCode.Combine(Package, At);
}

/// <summary>An online source of advisories: the seam the lookups go through, so tests need no network.</summary>
public interface IAdvisorySource
{
    /// <summary>The advisories for the package's exact version; <c>null</c> when the source couldn't be asked (offline, refused, garbled).</summary>
    Task<IReadOnlyList<Advisory>?> AdvisoriesAsync(PackageQuery package, CancellationToken cancellationToken);
}

/// <summary>
/// The opt-in lookups' results, kept on disk (<c>trust-lookups.json</c> beside the keyring) so the
/// checks read them without going online: the planner stays pure and an offline machine keeps the
/// last answers. Names, versions and advisory ids only.
/// </summary>
public sealed record TrustLookups(IReadOnlyList<PackageVerdict> Packages)
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 1;

    /// <summary>How old an answer may be before it is asked again.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(1);

    public static readonly TrustLookups Empty = new([]);

    /// <summary>The answer for <paramref name="package"/>; <c>null</c> when it wasn't asked.</summary>
    public PackageVerdict? For(PackageQuery package) => Packages.FirstOrDefault(p => p.Package.Matches(package));

    /// <summary>The packages to ask about: never asked, asked a day ago, or "asked" in the future (a clock set back).</summary>
    public IReadOnlyList<PackageQuery> Due(IEnumerable<PackageQuery> packages, DateTimeOffset now) =>
        [.. packages.DistinctBy(p => (p.Ecosystem, p.Name.ToLowerInvariant(), p.Version))
            .Where(p => For(p) is not { At: var at } || now - at >= MaxAge || at > now)];

    /// <summary>
    /// The answers for <paramref name="installed"/> only, <paramref name="fresh"/> ones replacing old: a
    /// package no longer installed, or at another version, is forgotten.
    /// </summary>
    public TrustLookups With(IEnumerable<PackageVerdict> fresh, IEnumerable<PackageQuery> installed)
    {
        var answers = fresh.ToArray();
        return new([.. installed.Select(p => answers.FirstOrDefault(a => a.Package.Matches(p)) ?? For(p)).OfType<PackageVerdict>()
            .DistinctBy(v => (v.Package.Ecosystem, v.Package.Name.ToLowerInvariant(), v.Package.Version))]);
    }

    /// <summary>
    /// Asks <paramref name="source"/> about the tools whose answer is due and keeps the rest. A
    /// package the source couldn't answer keeps its last answer, or stays unasked.
    /// </summary>
    public async Task<TrustLookups> RefreshAsync(IEnumerable<GlobalTool> tools, IAdvisorySource source, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        PackageQuery[] installed = [.. tools.Select(PackageQuery.Of).OfType<PackageQuery>()];
        List<PackageVerdict> fresh = [];
        foreach (var package in Due(installed, now))
            if (await source.AdvisoriesAsync(package, cancellationToken) is { } advisories)
                fresh.Add(new(package, now, advisories));
        return With(fresh, installed);
    }

    public string ToJson() => JsonSerializer.Serialize(new
    {
        version = Version,
        packages = Packages.Select(p => new
        {
            ecosystem = p.Package.Ecosystem,
            name = p.Package.Name,
            version = p.Package.Version,
            at = p.At,
            advisories = p.Advisories.Select(a => new { id = a.Id, summary = a.Summary, @fixed = a.Fixed }),
        }),
    });

    /// <summary>The answers in <paramref name="json"/>; <c>null</c> when missing, damaged or another version, so they are asked again.</summary>
    public static TrustLookups? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number || version.GetInt32() != Version
                || !root.TryGetProperty("packages", out var packages) || packages.ValueKind != JsonValueKind.Array)
                return null;
            List<PackageVerdict> list = [];
            foreach (var package in packages.EnumerateArray())
            {
                if (package.ValueKind != JsonValueKind.Object
                    || Doctor.Text(package, "ecosystem") is not { } ecosystem || Doctor.Text(package, "name") is not { } name || Doctor.Text(package, "version") is not { } v
                    || !package.TryGetProperty("at", out var at) || at.ValueKind != JsonValueKind.String || !at.TryGetDateTimeOffset(out var asked)
                    || !package.TryGetProperty("advisories", out var advisories) || advisories.ValueKind != JsonValueKind.Array)
                    return null;
                List<Advisory> found = [];
                foreach (var advisory in advisories.EnumerateArray())
                {
                    if (advisory.ValueKind != JsonValueKind.Object || Doctor.Text(advisory, "id") is not { } id)
                        return null;
                    found.Add(new(id, Doctor.Text(advisory, "summary"), Doctor.Text(advisory, "fixed")));
                }
                list.Add(new(new(ecosystem, name, v), asked, found));
            }
            return new(list);
        }
        catch (Exception e) when (e is JsonException or FormatException or InvalidOperationException)
        {
            return null;
        }
    }
}

/// <summary>
/// <see href="https://osv.dev">OSV.dev</see>'s query API: what is sent for a package and how its
/// answer is read. The HTTP call itself is the agent's.
/// </summary>
public static class Osv
{
    public static readonly Uri QueryUrl = new("https://api.osv.dev/v1/query");

    /// <summary>The request body: the package's name, ecosystem and version, nothing else.</summary>
    public static string QueryJson(PackageQuery package) =>
        JsonSerializer.Serialize(new { package = new { name = package.Name, ecosystem = package.Ecosystem }, version = package.Version });

    /// <summary>
    /// The advisories in an answer to <see cref="QueryJson"/>, each with the lowest version above the
    /// installed one that fixes it for this package; <c>null</c> when the answer isn't OSV's.
    /// </summary>
    public static IReadOnlyList<Advisory>? Parse(string? json, PackageQuery package)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            if (!root.TryGetProperty("vulns", out var vulns))
                return [];
            if (vulns.ValueKind != JsonValueKind.Array)
                return null;
            List<Advisory> advisories = [];
            foreach (var vuln in vulns.EnumerateArray())
            {
                if (vuln.ValueKind != JsonValueKind.Object || Doctor.Text(vuln, "id") is not { } id)
                    return null;
                advisories.Add(new(id, Doctor.Text(vuln, "summary"), Fixed(vuln, package)));
            }
            return advisories;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// The version that fixes the advisory for the installed one: the highest fix among the ranges
    /// (<c>introduced</c> to <c>fixed</c>) that hold the installed version, or <c>null</c> when one of
    /// them has no fix. A range of commits (<c>GIT</c>) says nothing about versions and is skipped.
    /// When no range is seen to hold it (OSV matched on its own version scheme, or on a list of
    /// versions), the lowest fix above it is named, as the best guess.
    /// </summary>
    static string? Fixed(JsonElement vuln, PackageQuery package)
    {
        if (!vuln.TryGetProperty("affected", out var affected) || affected.ValueKind != JsonValueKind.Array)
            return null;
        List<(string? Fix, bool Holds)> intervals = [];
        foreach (var entry in affected.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object || !entry.TryGetProperty("package", out var p) || p.ValueKind != JsonValueKind.Object
                || !string.Equals(Doctor.Text(p, "name"), package.Name, StringComparison.OrdinalIgnoreCase) || Doctor.Text(p, "ecosystem") != package.Ecosystem
                || !entry.TryGetProperty("ranges", out var ranges) || ranges.ValueKind != JsonValueKind.Array)
                continue;
            foreach (var range in ranges.EnumerateArray())
                if (range.ValueKind == JsonValueKind.Object && Doctor.Text(range, "type") != "GIT"
                    && range.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
                    intervals.AddRange(Intervals(events, package.Version));
        }
        var holding = intervals.Where(i => i.Holds).ToArray();
        if (holding.Length > 0)
            return holding.Any(i => i.Fix is null) ? null : holding.Select(i => i.Fix!).Order(VersionOrder).Last();
        return intervals.Select(i => i.Fix).OfType<string>().Where(f => VersionOrder.Compare(f, package.Version) > 0).Order(VersionOrder).FirstOrDefault();
    }

    /// <summary>
    /// A range's affected intervals, in OSV's event order: each from an <c>introduced</c> to a
    /// <c>fixed</c> (its fix), a <c>last_affected</c> or <c>limit</c> (no fix), or open (no fix);
    /// with whether it holds <paramref name="installed"/>.
    /// </summary>
    static IEnumerable<(string? Fix, bool Holds)> Intervals(JsonElement events, string installed)
    {
        string? from = null;
        foreach (var e in events.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object))
        {
            if (Doctor.Text(e, "introduced") is { } introduced)
            {
                if (from is not null)
                    yield return (null, Above(installed, from));
                from = introduced;
            }
            else if (from is not null && Doctor.Text(e, "fixed") is { } fix)
            {
                yield return (fix, Above(installed, from) && VersionOrder.Compare(installed, fix) < 0);
                from = null;
            }
            else if (from is not null && (Doctor.Text(e, "last_affected") ?? Doctor.Text(e, "limit")) is { } last)
            {
                yield return (null, Above(installed, from) && VersionOrder.Compare(installed, last) <= (Doctor.Text(e, "limit") is null ? 0 : -1));
                from = null;
            }
        }
        if (from is not null)
            yield return (null, Above(installed, from));
    }

    /// <summary>Whether <paramref name="version"/> is at or above <paramref name="introduced"/>; <c>0</c> is the start of time.</summary>
    static bool Above(string version, string introduced) => introduced == "0" || VersionOrder.Compare(version, introduced) >= 0;

    /// <summary>
    /// Dotted numbers compared as numbers, a pre-release (<c>-beta</c>) before its release; loose on
    /// purpose, since each ecosystem has its own scheme and this only picks which fix to name.
    /// </summary>
    public static readonly Comparer<string> VersionOrder = Comparer<string>.Create((a, b) =>
    {
        var (aCore, aPre) = Split(a);
        var (bCore, bPre) = Split(b);
        for (var i = 0; i < Math.Max(aCore.Length, bCore.Length); i++)
        {
            var (x, y) = (i < aCore.Length ? aCore[i] : "0", i < bCore.Length ? bCore[i] : "0");
            var order = long.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out var nx) && long.TryParse(y, NumberStyles.None, CultureInfo.InvariantCulture, out var ny)
                ? nx.CompareTo(ny) : string.CompareOrdinal(x, y);
            if (order != 0)
                return order;
        }
        return (aPre, bPre) switch
        {
            (null, null) => 0,
            (null, _) => 1,
            (_, null) => -1,
            _ => string.CompareOrdinal(aPre, bPre),
        };
    });

    static (string[] Core, string? Pre) Split(string version)
    {
        var plus = version.IndexOf('+', StringComparison.Ordinal);
        if (plus >= 0)
            version = version[..plus];
        var dash = version.IndexOf('-', StringComparison.Ordinal);
        return dash < 0 ? (version.Split('.'), null) : (version[..dash].Split('.'), version[(dash + 1)..]);
    }
}

/// <summary>
/// Update a global tool with the manager that installed it: the latest version, which holds every
/// published fix. Copied, not run: for the managers <see cref="Packages"/> can't run (pipx, cargo).
/// </summary>
/// <param name="Fixed">The version that fixes the advisory, when known: said, not pinned.</param>
public sealed record UpdateGlobalTool(string Manager, string Id, string? Fixed) : DoctorFix
{
    public override string Instruction => Manager switch
    {
        "dotnet" => $"dotnet tool update --global {Id}",
        "npm" => $"npm install --global {Id}@latest",
        "pipx" => $"pipx upgrade {Id}",
        _ => $"cargo install {Id}",
    };
}

/// <summary>Uninstall a global tool no published version fixes; copied, like <see cref="UpdateGlobalTool"/>.</summary>
public sealed record UninstallGlobalTool(string Manager, string Id) : DoctorFix
{
    public override string Instruction => Manager switch
    {
        "dotnet" => $"dotnet tool uninstall --global {Id}",
        "npm" => $"npm uninstall --global {Id}",
        "pipx" => $"pipx uninstall {Id}",
        _ => $"cargo uninstall {Id}",
    };
}

public static partial class Doctor
{
    public const string VulnerableToolKind = "global tools with a known vulnerability";

    /// <summary>The source each lookup answer came from, as findings name it.</summary>
    public const string OsvSource = "OSV.dev";

    /// <summary>
    /// The global tools OSV reports an advisory for at their installed version, from the opt-in
    /// lookups' saved answers (<paramref name="lookups"/> is <c>null</c> while they are off: no
    /// finding then, since nothing was asked). A new advisory is a new reason, so a dismissal comes
    /// back for it; trust in a publisher never hides one. The fix is a <see cref="PackageFix"/> the
    /// app runs after approval where <see cref="Packages"/> builds one (dotnet, npm), else a command to copy.
    /// </summary>
    public static IEnumerable<DoctorCheck> KnownVulnerabilities(IEnumerable<GlobalTool> tools, TrustLookups? lookups)
    {
        if (lookups is null)
            yield break;
        foreach (var tool in tools.OrderBy(t => t.Manager, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.OrdinalIgnoreCase))
        {
            if (PackageQuery.Of(tool) is not { } package || lookups.For(package) is not { Advisories: { Count: > 0 } advisories })
                continue;
            var fixes = advisories.Select(a => a.Fixed).OfType<string>().ToArray();
            // Every advisory needs its fix; one without any can't be updated away.
            var fixedAll = advisories.All(a => a.Fixed is not null);
            var ids = string.Join(", ", advisories.Select(a => a.Id));
            var highest = fixes.Order(Osv.VersionOrder).LastOrDefault();
            yield return new($"{tool.Id} {tool.Version} has {(advisories.Count == 1 ? "a known vulnerability" : $"{advisories.Count} known vulnerabilities")}",
                DoctorStatus.Warn,
                $"{OsvSource} lists {ids} for the {tool.Manager} global tool {tool.Id} {tool.Version}. "
                + (fixedAll ? $"Update it{(highest is null ? "" : $"; {highest} fixes {(advisories.Count == 1 ? "it" : "them all")}")}"
                    : "No version fixes every one of them: uninstall it unless you need it"),
                fixedAll ? (DoctorFix?)Packages.Update(tool) ?? new UpdateGlobalTool(tool.Manager, tool.Id, highest)
                    : (DoctorFix?)Packages.Uninstall(tool) ?? new UninstallGlobalTool(tool.Manager, tool.Id),
                Kind: VulnerableToolKind)
            {
                Item = $"tool {tool.Manager} {tool.Id}".ToLowerInvariant(),
                Reasons = [.. advisories.Select(a => $"advisory {a.Id}")],
            };
        }
    }
}
