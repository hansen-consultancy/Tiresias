using System.Globalization;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>The package managers and toolchains whose supply-chain settings the doctor judges (docs/supply-chain.md).</summary>
public enum Toolchain
{
    Npm,
    Pnpm,
    Yarn,
    Bun,
    NuGet,
    Pip,
    Uv,
    Go,
    Cargo,
    Gradle,
}

/// <summary>
/// A toolchain found on this machine: its version, when a file it installs says so, the user-level
/// files it reads its settings from, lowest precedence first, and the environment variables that
/// name one of its settings. The planner reads settings only, never a credential.
/// </summary>
/// <param name="Version"><c>null</c> when unknown.</param>
public sealed record DoctorToolchain(Toolchain Tool, string? Version, IReadOnlyList<DoctorFile> Settings, IReadOnlyDictionary<string, string> Variables);

/// <summary>Turn on a package manager's safeguard: its own command where it has one, else the line to add to its settings file.</summary>
public sealed record ChangeToolSetting(string Steps) : DoctorFix
{
    public override string Instruction => Steps;
}

public static partial class Doctor
{
    const string ScriptsKind = "package managers that run every dependency's install script";

    const string AgeKind = "package managers that install a release the minute it is published";

    /// <summary>The minimum release age the fixes suggest: a week, which most malicious releases don't survive.</summary>
    const int SuggestedDays = 7;

    /// <summary>
    /// For each toolchain found, whether its safeguards against a malicious package are on: install
    /// scripts that don't run unasked, a minimum age before a new release is installed, and, where
    /// the tool has them, audits, signatures and checksums. Judged by the tool's version, since a
    /// default often changed with one, and by its user-level settings. A project's own settings can
    /// still turn a safeguard off or on for that project; the lines say what the machine's default is.
    /// Lines name the tool, its version and the setting, never a file path or a registry.
    /// </summary>
    public static IEnumerable<DoctorCheck> SupplyChain(IEnumerable<DoctorToolchain> toolchains) =>
        toolchains.SelectMany(t => t.Tool switch
        {
            Toolchain.Npm => Npm(t),
            Toolchain.Pnpm => Pnpm(t),
            Toolchain.Yarn => Yarn(t),
            Toolchain.Bun => Bun(t),
            Toolchain.NuGet => NuGet(t),
            Toolchain.Pip => Pip(t),
            Toolchain.Uv => Uv(t),
            Toolchain.Go => Go(t),
            Toolchain.Cargo => Cargo(t),
            Toolchain.Gradle => Gradle(t),
            _ => [],
        }).Select(c => c with { Surface = true, ForDevelopers = true });

    /// <summary>The environment variables naming a setting the checks read; a fixed list, so a credential variable is never opened.</summary>
    public static readonly IReadOnlyList<string> ToolchainVariables =
    [
        "npm_config_ignore_scripts", "npm_config_min_release_age", "npm_config_before",
        "pnpm_config_minimum_release_age", "pnpm_config_dangerously_allow_all_builds",
        "npm_config_minimum_release_age", "npm_config_dangerously_allow_all_builds",
        "YARN_ENABLE_SCRIPTS", "YARN_NPM_MINIMAL_AGE_GATE",
        "PIP_UPLOADED_PRIOR_TO", "PIP_ONLY_BINARY",
        "UV_EXCLUDE_NEWER", "UV_NO_BUILD",
        "GOSUMDB",
        "CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE",
    ];

    /// <summary>Whether <paramref name="name"/> is a toolchain setting the probe may read the value of.</summary>
    public static bool IsToolchainVariable(string name) => ToolchainVariables.Contains(name, StringComparer.OrdinalIgnoreCase);

    static IEnumerable<DoctorCheck> Npm(DoctorToolchain tool)
    {
        var settings = ToolSettings.Of(tool, "npm_config_");
        var version = ToolVersion.Parse(tool.Version);
        var label = Label("npm", tool.Version);

        if (settings.Flag("ignore-scripts") == true)
            yield return Scripts("npm", DoctorStatus.Ok, $"{label} runs no install scripts: ignore-scripts is on");
        else if (version >= new Version(12, 0))
            yield return Scripts("npm", DoctorStatus.Ok, $"{label} runs a dependency's install script only when the project's allowScripts names it");
        else
            yield return Scripts("npm", DoctorStatus.Warn,
                $"{label} runs every dependency's install script as you, the moment it is installed. npm 12 runs only those a project allows",
                new ChangeToolSetting("npm install -g npm@latest; or, to keep this npm, npm config set ignore-scripts true"));

        if (settings.Number("min-release-age") is > 0 and var days)
            yield return Age("npm", DoctorStatus.Ok, $"{label} installs only releases at least {Days(days)} old (min-release-age)");
        else if (settings.Value("before") is not null)
            yield return Age("npm", DoctorStatus.Ok, $"{label} installs only releases published before a set date (before)");
        else if (version is null || version >= new Version(11, 10))
            yield return Age("npm", DoctorStatus.Warn, $"{label} installs a release the minute it is published, before anyone has noticed a malicious one",
                new ChangeToolSetting($"npm config set min-release-age {SuggestedDays}"));
        else
            yield return Age("npm", DoctorStatus.Warn, $"{label} installs a release the minute it is published, and has no minimum release age before npm 11.10",
                new ChangeToolSetting($"npm install -g npm@latest, then npm config set min-release-age {SuggestedDays}"));
    }

    static IEnumerable<DoctorCheck> Pnpm(DoctorToolchain tool)
    {
        var version = ToolVersion.Parse(tool.Version);
        // pnpm 11 reads its settings from config.yaml only, and pnpm_config_ variables; pnpm 10 from rc and .npmrc too.
        var eleven = version >= new Version(11, 0);
        var settings = ToolSettings.Of(tool with { Settings = [.. tool.Settings.Where(f => eleven == f.Path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))] },
            eleven ? "pnpm_config_" : "npm_config_");
        var label = Label("pnpm", tool.Version);

        if (settings.Flag("dangerously-allow-all-builds") == true)
            yield return Scripts("pnpm", DoctorStatus.Warn, $"{label} runs every dependency's build script: dangerouslyAllowAllBuilds is on",
                new ChangeToolSetting("pnpm config set dangerouslyAllowAllBuilds false"));
        else if (version is null || version >= new Version(10, 0))
            yield return Scripts("pnpm", DoctorStatus.Ok, $"{label} runs a dependency's build script only when the project's allowBuilds names it");
        else
            yield return Scripts("pnpm", DoctorStatus.Warn, $"{label} runs every dependency's install script as you. pnpm 10 runs only those a project allows",
                new ChangeToolSetting("npm install -g pnpm@latest (or pnpm self-update)"));

        var minutes = settings.Number("minimum-release-age");
        if (minutes is > 0)
            yield return Age("pnpm", DoctorStatus.Ok, $"{label} installs only releases at least {Days(minutes.Value / 1440)} old (minimumReleaseAge)");
        else if (minutes is null && eleven)
            yield return Age("pnpm", DoctorStatus.Ok, $"{label} installs only releases at least a day old, its default; a week catches more (minimumReleaseAge: {SuggestedDays * 1440})");
        else if (version is null || version >= new Version(10, 16))
            yield return Age("pnpm", DoctorStatus.Warn, $"{label} installs a release the minute it is published, before anyone has noticed a malicious one",
                new ChangeToolSetting($"pnpm config set minimumReleaseAge {SuggestedDays * 1440}"));
        else
            yield return Age("pnpm", DoctorStatus.Warn, $"{label} installs a release the minute it is published, and has no minimum release age before pnpm 10.16",
                new ChangeToolSetting($"pnpm self-update, then pnpm config set minimumReleaseAge {SuggestedDays * 1440}"));
    }

    /// <summary>
    /// Yarn 2 and later read <c>.yarnrc.yml</c>, and a project picks its own Yarn, so a version is
    /// rarely known: an unset setting is judged by what Yarn 4.14 and 4.15 made the default.
    /// </summary>
    static IEnumerable<DoctorCheck> Yarn(DoctorToolchain tool)
    {
        var version = ToolVersion.Parse(tool.Version);
        if (version is { Major: < 2 })
        {
            yield return Scripts("Yarn", DoctorStatus.Warn, $"{Label("Yarn", tool.Version)} runs every dependency's install script and has no minimum release age; Yarn 4 turns both on",
                new ChangeToolSetting("corepack enable, then yarn set version stable in each project"));
            yield break;
        }
        var settings = ToolSettings.Of(tool, "YARN_");
        var label = Label("Yarn", tool.Version);
        var known = version is not null;

        switch (settings.Flag("enable-scripts"))
        {
            case false:
                yield return Scripts("Yarn", DoctorStatus.Ok, $"{label} runs no dependency's install script unless the project allows it (enableScripts: false)");
                break;
            case true:
                yield return Scripts("Yarn", DoctorStatus.Warn, $"{label} runs every dependency's install script: enableScripts is on",
                    new ChangeToolSetting("yarn config set -H enableScripts false"));
                break;
            case null when known && version >= new Version(4, 14):
                yield return Scripts("Yarn", DoctorStatus.Ok, $"{label} runs no dependency's install script unless the project allows it, its default");
                break;
            default:
                yield return Scripts("Yarn", DoctorStatus.Warn, $"{label} runs every dependency's install script in projects on a Yarn before 4.14, which ran them by default",
                    new ChangeToolSetting("yarn config set -H enableScripts false"));
                break;
        }

        var gate = settings.Value("npm-minimal-age-gate");
        if (gate is not null && YarnDuration(gate) is { } minutes)
        {
            if (minutes > 0)
                yield return Age("Yarn", DoctorStatus.Ok, $"{label} installs only releases at least {Days(minutes / 1440)} old (npmMinimalAgeGate)");
            else
                yield return Age("Yarn", DoctorStatus.Warn, $"{label} installs a release the minute it is published: npmMinimalAgeGate is 0",
                    new ChangeToolSetting($"yarn config set -H npmMinimalAgeGate {SuggestedDays}d"));
        }
        else if (known && version >= new Version(4, 15))
            yield return Age("Yarn", DoctorStatus.Ok, $"{label} installs only releases at least a day old, its default; a week catches more (npmMinimalAgeGate: {SuggestedDays}d)");
        else
            yield return Age("Yarn", DoctorStatus.Warn, $"{label} installs a release the minute it is published in projects on a Yarn before 4.15, which had no age gate by default",
                new ChangeToolSetting($"yarn config set -H npmMinimalAgeGate {SuggestedDays}d"));
    }

    /// <summary>
    /// Bun runs install scripts only for the packages a project trusts, or for its built-in list of
    /// popular ones when the project names none. Its minimum release age is in seconds, read from
    /// <c>[install]</c> of the global <c>.bunfig.toml</c>.
    /// </summary>
    static IEnumerable<DoctorCheck> Bun(DoctorToolchain tool)
    {
        var settings = ToolSettings.Of(tool, null);
        var label = Label("Bun", tool.Version);

        yield return settings.Flag("install.ignore-scripts") == true
            ? Scripts("Bun", DoctorStatus.Ok, $"{label} runs no install scripts: ignoreScripts is on")
            : Scripts("Bun", DoctorStatus.Ok, $"{label} runs a dependency's install script only when the project trusts it, or it is on Bun's list of popular packages");

        yield return settings.Number("install.minimum-release-age") is > 0 and var seconds
            ? Age("Bun", DoctorStatus.Ok, $"{label} installs only releases at least {Days(seconds / 86400)} old (minimumReleaseAge)")
            : Age("Bun", DoctorStatus.Warn, $"{label} installs a release the minute it is published, before anyone has noticed a malicious one",
                new ChangeToolSetting($"add minimumReleaseAge = {SuggestedDays * 86400} under [install] in .bunfig.toml in your user folder (Bun 1.3 or later)"));
    }

    /// <summary>
    /// NuGet runs no install script with PackageReference, but a package's build targets run when
    /// the project builds, and nothing turns that off. Its minimum publish age (SDK 11) is set per
    /// source in the user's NuGet.Config, and gates adding and updating packages, not a restore of a
    /// version already pinned. Its version is the newest SDK's.
    /// </summary>
    static IEnumerable<DoctorCheck> NuGet(DoctorToolchain tool)
    {
        var version = ToolVersion.Parse(tool.Version);
        var label = Label(".NET SDK", tool.Version);
        var config = tool.Settings.Select(f => f.Text is null ? null : EnvironmentVariables.NuGetConfig.Safeguards(f.Text)).LastOrDefault(s => s is not null);

        yield return Scripts("NuGet", DoctorStatus.Ok, $"{label} runs no install script; a package's build targets still run when you build");

        var sources = config?.Sources ?? [];
        var gated = sources.Count(s => s.Hours > 0);
        var source = sources.Any(s => s.Source.Equals("nuget.org", StringComparison.OrdinalIgnoreCase)) || sources.Count == 0 ? "nuget.org" : "<source>";
        if (gated > 0 && gated == sources.Count)
            yield return Age("NuGet", DoctorStatus.Ok,
                $"{label} adds and updates only packages at least {Days(sources.Min(s => s.Hours) / 24.0)} old (minPublishAgeHours on every source)");
        else if (version is null || version >= new Version(11, 0, 100))
            yield return Age("NuGet", DoctorStatus.Warn,
                gated > 0
                    ? $"{label} gates {gated} of {sources.Count} sources by age: the others add a release the minute it is published"
                    : $"{label} adds and updates to a release the minute it is published, before anyone has noticed a malicious one",
                new ChangeToolSetting($"dotnet nuget update source {source} --min-publish-age-hours {SuggestedDays * 24}"));
        else
            yield return Age("NuGet", DoctorStatus.Warn,
                $"{label} adds a release the minute it is published; a minimum publish age per source needs the .NET 11 SDK. Until then, a package such as NuGetCooldown can fail a build that resolves a new release",
                new ChangeToolSetting($"install the .NET 11 SDK, then dotnet nuget update source {source} --min-publish-age-hours {SuggestedDays * 24}"));

        // Every nuget.org package is repository-signed and checked on restore; require adds a pinned list of signers.
        yield return string.Equals(config?.SignatureValidationMode, "require", StringComparison.OrdinalIgnoreCase)
            ? new("NuGet signatures", DoctorStatus.Ok, $"{label} installs only packages signed by a trusted signer (signatureValidationMode: require)")
            : new("NuGet signatures", DoctorStatus.Ok,
                $"{label} checks a package's signature when it has one, and accepts an unsigned one. Requiring a trusted signer refuses a package from anyone else, such as one pushed to another feed under a known name",
                new ChangeToolSetting("dotnet nuget trust source nuget.org, then dotnet nuget config set signatureValidationMode require"),
                Kind: "package managers that accept unsigned packages");
    }

    /// <summary>
    /// pip builds a source distribution by running its build code, the install script of Python;
    /// installing wheels only avoids it, but fails for a package that ships none, so it is suggested
    /// rather than warned about. <c>uploaded-prior-to</c> came in pip 26.0, and a relative <c>P7D</c> in 26.1.
    /// </summary>
    static IEnumerable<DoctorCheck> Pip(DoctorToolchain tool)
    {
        var settings = ToolSettings.Of(tool, "PIP_");
        var version = ToolVersion.Parse(tool.Version);
        var label = Label("pip", tool.Version);
        string? Value(string key) => settings.Value(key) ?? settings.Value("install." + key) ?? settings.Value("global." + key);

        yield return Value("only-binary") is { } binary && binary.Contains(":all:", StringComparison.OrdinalIgnoreCase)
            ? Scripts("pip", DoctorStatus.Ok, $"{label} installs wheels only, so no package's build code runs (only-binary: :all:)")
            : new("pip install scripts", DoctorStatus.Ok,
                $"{label} runs a package's build code when it has no wheel for this machine. Installing wheels only stops that, and fails for the few packages without one",
                new ChangeToolSetting("pip config set global.only-binary :all:"), Kind: BuildKind);

        if (Value("uploaded-prior-to") is not null)
            yield return Age("pip", DoctorStatus.Ok, $"{label} installs only releases uploaded before a set age or date (uploaded-prior-to)");
        else if (version is null || version >= new Version(26, 1))
            yield return Age("pip", DoctorStatus.Warn, $"{label} installs a release the minute it is uploaded, before anyone has noticed a malicious one",
                new ChangeToolSetting($"pip config set global.uploaded-prior-to P{SuggestedDays}D"));
        else
            yield return Age("pip", DoctorStatus.Warn, $"{label} installs a release the minute it is uploaded; a relative uploaded-prior-to needs pip 26.1",
                new ChangeToolSetting($"python -m pip install --upgrade pip, then pip config set global.uploaded-prior-to P{SuggestedDays}D"));
    }

    const string BuildKind = "package managers that build packages from source";

    /// <summary>uv reads <c>uv.toml</c> in the user's roaming folder; <c>exclude-newer</c> takes a duration since uv 0.9.17.</summary>
    static IEnumerable<DoctorCheck> Uv(DoctorToolchain tool)
    {
        var settings = ToolSettings.Of(tool, "UV_");
        var version = ToolVersion.Parse(tool.Version);
        var label = Label("uv", tool.Version);

        yield return settings.Flag("no-build") == true
            ? Scripts("uv", DoctorStatus.Ok, $"{label} installs wheels only, so no package's build code runs (no-build)")
            : new("uv install scripts", DoctorStatus.Ok,
                $"{label} runs a package's build code when it has no wheel for this machine. no-build stops that, and fails for the few packages without one",
                new ChangeToolSetting("add no-build = true to uv.toml in %APPDATA%\\uv"), Kind: BuildKind);

        var newer = settings.Value("exclude-newer");
        if (newer is not null && !newer.Equals("false", StringComparison.OrdinalIgnoreCase))
            yield return Age("uv", DoctorStatus.Ok, $"{label} installs only releases older than its exclude-newer setting");
        else
            yield return Age("uv", DoctorStatus.Warn, $"{label} installs a release the minute it is published, before anyone has noticed a malicious one",
                new ChangeToolSetting((version is not null && version < new Version(0, 9, 17) ? "uv self update, then add " : "add ")
                    + $"exclude-newer = \"{SuggestedDays} days\" to uv.toml in %APPDATA%\\uv"));
    }

    /// <summary>
    /// Go runs no code from a module it downloads, and checks every module against the checksum
    /// database unless <c>GOSUMDB</c> is off. It has no minimum release age.
    /// </summary>
    static IEnumerable<DoctorCheck> Go(DoctorToolchain tool)
    {
        var settings = ToolSettings.Of(tool, "");
        var label = Label("Go", tool.Version);
        yield return Scripts("Go", DoctorStatus.Ok, $"{label} runs no code from a module when it downloads it");
        yield return string.Equals(settings.Value("GOSUMDB"), "off", StringComparison.OrdinalIgnoreCase)
            ? new("Go checksums", DoctorStatus.Warn, $"{label} doesn't check modules against the checksum database: GOSUMDB is off, so a changed release goes unnoticed",
                new ChangeToolSetting("go env -u GOSUMDB, and remove a GOSUMDB=off environment variable"))
            : new("Go checksums", DoctorStatus.Ok, $"{label} checks every public module against the checksum database");
    }

    /// <summary>Cargo runs a crate's <c>build.rs</c> when it builds, and nothing turns that off. Its minimum publish age is stable since 1.100.</summary>
    static IEnumerable<DoctorCheck> Cargo(DoctorToolchain tool)
    {
        var settings = ToolSettings.Of(tool, "CARGO_");
        var version = ToolVersion.Parse(tool.Version);
        var label = Label("Cargo", tool.Version);
        yield return Scripts("Cargo", DoctorStatus.Ok, $"{label} runs a crate's build script when it builds, which no setting stops");
        var age = settings.Value("registry.global-min-publish-age");
        yield return age is not null && age.Trim() != "0"
            ? Age("Cargo", DoctorStatus.Ok, $"{label} resolves only crates published at least {age} ago (global-min-publish-age)")
            : Age("Cargo", DoctorStatus.Warn, $"{label} resolves a release the minute it is published, before anyone has noticed a malicious one",
                new ChangeToolSetting((version is not null && version < new Version(1, 100) ? "rustup update, then add " : "add ")
                    + $"global-min-publish-age = \"{SuggestedDays} days\" under [registry] in .cargo\\config.toml in your user folder (Cargo 1.100 or later)"));
    }

    /// <summary>
    /// Gradle verifies dependencies per project, from its <c>verification-metadata.xml</c>; the user's
    /// <c>gradle.properties</c> can only weaken that, for every project.
    /// </summary>
    static IEnumerable<DoctorCheck> Gradle(DoctorToolchain tool)
    {
        var mode = ToolSettings.Of(tool, null).Value("org.gradle.dependency.verification");
        var label = Label("Gradle", tool.Version);
        yield return mode is not null && (mode.Equals("off", StringComparison.OrdinalIgnoreCase) || mode.Equals("lenient", StringComparison.OrdinalIgnoreCase))
            ? new("Gradle verification", DoctorStatus.Warn,
                $"{label} doesn't stop on a dependency that fails a project's verification: your gradle.properties sets it to {mode.ToLowerInvariant()} for every project",
                new ChangeToolSetting("remove org.gradle.dependency.verification from gradle.properties in .gradle in your user folder"))
            : new("Gradle verification", DoctorStatus.Ok, $"{label} stops on a dependency that fails a project's verification-metadata.xml, in projects that have one");
    }

    static DoctorCheck Scripts(string tool, DoctorStatus status, string detail, DoctorFix? fix = null) =>
        new($"{tool} install scripts", status, detail, fix, Kind: fix is null ? null : ScriptsKind);

    static DoctorCheck Age(string tool, DoctorStatus status, string detail, DoctorFix? fix = null) =>
        new($"{tool} release age", status, detail, fix, Kind: fix is null ? null : AgeKind);

    static string Label(string tool, string? version) => version is null ? $"{tool} (version unknown)" : $"{tool} {version}";

    static string Days(double days) => days switch
    {
        < 1 => "less than a day",
        < 1.5 => "a day",
        _ => $"{Math.Round(days).ToString(CultureInfo.InvariantCulture)} days",
    };

    /// <summary>A Yarn duration in minutes: a bare number is minutes, else a number with <c>m</c>, <c>h</c>, <c>d</c> or <c>w</c>.</summary>
    static double? YarnDuration(string value)
    {
        var match = DurationPattern().Match(value.Trim());
        if (!match.Success || !double.TryParse(match.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var amount))
            return null;
        return match.Groups[2].Value.ToLowerInvariant() switch
        {
            "" or "m" => amount,
            "h" => amount * 60,
            "d" => amount * 1440,
            "w" => amount * 10080,
            _ => null,
        };
    }

    [GeneratedRegex(@"^(\d+(?:\.\d+)?)\s*([mhdw]?)$", RegexOptions.IgnoreCase)]
    private static partial Regex DurationPattern();
}

/// <summary>A toolchain's version as the comparisons need it: <c>v12.2.3-beta.1</c> as 12.2.3.</summary>
public static partial class ToolVersion
{
    public static Version? Parse(string? text)
    {
        if (text is null || Leading().Match(text.Trim()) is not { Success: true } match)
            return null;
        return Version.TryParse(match.Groups[1].Value.Contains('.', StringComparison.Ordinal) ? match.Groups[1].Value : match.Groups[1].Value + ".0", out var version) ? version : null;
    }

    [GeneratedRegex(@"^v?(\d+(?:\.\d+){0,3})")]
    private static partial Regex Leading();
}

/// <summary>
/// One toolchain's settings, read from its files the forgiving way the doctor needs: INI, TOML and
/// top-level YAML lines of <c>key = value</c> or <c>key: value</c>, a <c>[section]</c> prefixing the
/// keys under it. Keys compare without case, dots, dashes or underscores, so <c>min-release-age</c>,
/// <c>minReleaseAge</c> and <c>MIN_RELEASE_AGE</c> are one. A later file wins, and an environment
/// variable wins over every file, as the tools do.
/// </summary>
sealed partial class ToolSettings
{
    readonly Dictionary<string, string> values = new(StringComparer.Ordinal);

    /// <param name="prefix">The prefix the tool's setting variables carry, such as <c>npm_config_</c>; <c>null</c> reads none.</param>
    public static ToolSettings Of(DoctorToolchain tool, string? prefix)
    {
        var settings = new ToolSettings();
        foreach (var file in tool.Settings)
            if (file.Text is { } text)
                settings.Read(text);
        if (prefix is not null)
            foreach (var (name, value) in tool.Variables)
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    settings.values[Key(name[prefix.Length..])] = value;
        return settings;
    }

    void Read(string text)
    {
        var section = "";
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
                continue;
            if (line[0] == '[' && line.IndexOf(']', StringComparison.Ordinal) is > 0 and var close)
            {
                section = line[1..close].Trim() + ".";
                continue;
            }
            // Nested YAML is never a setting the doctor reads.
            if (raw.Length > 0 && raw[0] is ' ' or '\t' && section.Length == 0)
                continue;
            if (Line().Match(line) is { Success: true } match)
                values[Key(section + match.Groups["key"].Value)] = Unquote(match.Groups["value"].Value);
        }
    }

    public string? Value(string key) => values.TryGetValue(Key(key), out var value) && value.Length > 0 ? value : null;

    public bool? Flag(string key) => Value(key)?.ToLowerInvariant() switch
    {
        "true" or "1" or "yes" => true,
        "false" or "0" or "no" => false,
        _ => null,
    };

    public double? Number(string key) =>
        double.TryParse(Value(key), NumberStyles.Float, CultureInfo.InvariantCulture, out var number) ? number : null;

    static string Key(string key) => new([.. key.Where(c => c is not '-' and not '_' and not '.').Select(char.ToLowerInvariant)]);

    static string Unquote(string value)
    {
        var hash = value.IndexOf(" #", StringComparison.Ordinal);
        if (hash >= 0 && value[0] is not '"' and not '\'')
            value = value[..hash].TrimEnd();
        return value.Length >= 2 && value[0] is '"' or '\'' && value[^1] == value[0] ? value[1..^1] : value;
    }

    [GeneratedRegex(@"^(?<key>[A-Za-z0-9_.\-]+)\s*[=:]\s*(?<value>.*?)\s*$")]
    private static partial Regex Line();
}
