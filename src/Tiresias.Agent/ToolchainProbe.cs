using System.Diagnostics;
using System.Text.Json;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// Finds the package managers and toolchains on this machine and reads the user-level files they
/// take their settings from (docs/supply-chain.md). No process starts: a version comes from a file
/// the tool installs beside itself, or is unknown. <c>PATH</c>, Program Files and the machine's
/// environment are this PC's, so a demo reads only its made-up profile.
/// </summary>
static class ToolchainProbe
{
    public static IEnumerable<DoctorToolchain> Read()
    {
        var profile = UserMachine.Folder(Environment.SpecialFolder.UserProfile);
        var roaming = UserMachine.Folder(Environment.SpecialFolder.ApplicationData);
        var local = UserMachine.Folder(Environment.SpecialFolder.LocalApplicationData);
        var path = DemoMode.On ? [] : PathFolders();
        var variables = Variables();

        string? On(params string[] files) => path.SelectMany(d => files.Select(f => Path.Combine(d, f))).FirstOrDefault(File.Exists);
        DoctorFile[] Files(params string[] paths) => [.. paths.Where(File.Exists).Select(Read)];

        var npm = Doctor.FindNodeShim(path, "npm");
        var npmrc = Path.Combine(profile, ".npmrc");
        if (npm is not null)
            yield return new(Toolchain.Npm, PackageVersion(npm, "npm"), Files(Doctor.NpmSettingsFiles(profile, Path.GetDirectoryName(npm)!)), variables);

        var pnpm = Doctor.FindNodeShim(path, "pnpm");
        if (pnpm is not null)
            yield return new(Toolchain.Pnpm, PackageVersion(pnpm, "pnpm"),
                Files(npmrc, Path.Combine(local, "pnpm", "config", "rc"), Path.Combine(local, "pnpm", "config", "config.yaml")), variables);

        var yarnrc = Path.Combine(profile, ".yarnrc.yml");
        var yarn = Doctor.FindNodeShim(path, "yarn");
        if (yarn is not null || File.Exists(yarnrc))
            yield return new(Toolchain.Yarn, yarn is null ? null : PackageVersion(yarn, "yarn"), Files(yarnrc), variables);

        var bunfig = Path.Combine(profile, ".bunfig.toml");
        var bun = On("bun.exe") ?? (File.Exists(Path.Combine(profile, ".bun", "bin", "bun.exe")) ? Path.Combine(profile, ".bun", "bin", "bun.exe") : null);
        if (bun is not null)
            yield return new(Toolchain.Bun, FileVersion(bun), Files(bunfig, Path.Combine(roaming, ".bunfig.toml")), variables);

        var sdk = DemoMode.On ? null : DotNetSdk(On("dotnet.exe"));
        if (sdk is not null)
            yield return new(Toolchain.NuGet, sdk, Files(Path.Combine(roaming, "NuGet", "NuGet.Config")), variables);

        var pip = On("pip.exe", "pip3.exe");
        if (pip is not null)
            yield return new(Toolchain.Pip, PipVersion(pip) ?? FileVersion(pip), Files(Doctor.PipSettingsFiles(profile, roaming)), variables);

        var uv = On("uv.exe");
        if (uv is not null)
            yield return new(Toolchain.Uv, Read(Path.Combine(local, "uv", "uv-receipt.json")).Text is { } receipt ? JsonVersion(receipt) : null, Files(Path.Combine(roaming, "uv", "uv.toml")), variables);

        var go = On("go.exe");
        if (go is not null)
            yield return new(Toolchain.Go, GoVersion(go), Files(Path.Combine(roaming, "go", "env")), variables);

        var cargoHome = Path.Combine(profile, ".cargo");
        if (On("cargo.exe") is not null || File.Exists(Path.Combine(cargoHome, "bin", "cargo.exe")))
            yield return new(Toolchain.Cargo, null, Files(Path.Combine(cargoHome, "config"), Path.Combine(cargoHome, "config.toml")), variables);

        var gradleProperties = Path.Combine(profile, ".gradle", "gradle.properties");
        if (On("gradle.bat") is not null || File.Exists(gradleProperties))
            yield return new(Toolchain.Gradle, null, Files(gradleProperties), variables);
    }

    static string[] PathFolders() =>
        [.. (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(d => Environment.ExpandEnvironmentVariables(d.Trim('"'))).Where(Path.IsPathFullyQualified)];

    /// <summary>
    /// The user's and the machine's environment variables that name a toolchain setting
    /// (<see cref="Doctor.IsToolchainVariable"/>), the user's winning, as a new terminal sees them.
    /// Settings only: a credential variable never matches.
    /// </summary>
    static IReadOnlyDictionary<string, string> Variables()
    {
        var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!DemoMode.On)
            Add(Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Machine));
        if (!DemoMode.On)
            Add(Environment.GetEnvironmentVariables(EnvironmentVariableTarget.User));
        else
            foreach (var name in Doctor.ToolchainVariables)
                if (UserMachine.UserVariable(name) is { } value)
                    found[name] = value;
        return found;

        void Add(System.Collections.IDictionary variables)
        {
            foreach (System.Collections.DictionaryEntry entry in variables)
                if (entry.Key is string name && Doctor.IsToolchainVariable(name) && entry.Value is string value)
                    found[name] = value;
        }
    }

    /// <summary>The version in <c>node_modules\<paramref name="package"/>\package.json</c> beside an npm-installed shim.</summary>
    static string? PackageVersion(string shim, string package)
    {
        if (Read(Path.Combine(Path.GetDirectoryName(shim)!, "node_modules", package, "package.json")).Text is { } text)
            return JsonVersion(text);
        return shim.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? FileVersion(shim) : null;
    }

    static string? JsonVersion(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("version", out var version)
                && version.ValueKind == JsonValueKind.String ? version.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The newest SDK folder beside <c>dotnet.exe</c>, else in Program Files.</summary>
    static string? DotNetSdk(string? dotnet)
    {
        var folder = Path.Combine(dotnet is null ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet") : Path.GetDirectoryName(dotnet)!, "sdk");
        if (!Directory.Exists(folder))
            return null;
        return Directory.EnumerateDirectories(folder).Select(Path.GetFileName).OfType<string>()
            .Where(n => ToolVersion.Parse(n) is not null).OrderByDescending(n => ToolVersion.Parse(n)).FirstOrDefault();
    }

    /// <summary>pip's version from its <c>dist-info</c> folder, in <c>Lib\site-packages</c> beside the <c>Scripts</c> folder <c>pip.exe</c> is in.</summary>
    static string? PipVersion(string pip)
    {
        var packages = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(pip)!) ?? "", "Lib", "site-packages");
        if (!Directory.Exists(packages))
            return null;
        return Directory.EnumerateDirectories(packages, "pip-*.dist-info").Select(d => Path.GetFileName(d)["pip-".Length..^".dist-info".Length])
            .Where(v => ToolVersion.Parse(v) is not null).OrderByDescending(v => ToolVersion.Parse(v)).FirstOrDefault();
    }

    /// <summary>Go's <c>VERSION</c> file in its root, the folder above <c>bin\go.exe</c>: its first line is <c>go1.25.3</c>.</summary>
    static string? GoVersion(string go) =>
        Read(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(go)!) ?? "", "VERSION")).Text?.Split('\n')[0].Trim() is { } line && line.StartsWith("go", StringComparison.Ordinal)
            ? line[2..] : null;

    /// <summary>The program file's own product version, when it has one.</summary>
    static string? FileVersion(string program)
    {
        try
        {
            return FileVersionInfo.GetVersionInfo(program).ProductVersion is { Length: > 0 } version ? version : null;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    static DoctorFile Read(string path)
    {
        try
        {
            return new(path, File.Exists(path) ? File.ReadAllText(path) : null);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new(path, null);
        }
    }
}
