using System.IO.Enumeration;
using System.Net.Sockets;
using Tiresias.Client;
using Tiresias.EnvironmentVariables;
using Tiresias.Protocol;
using Tiresias.Vault;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace Tiresias.Agent;

/// <summary>The facts <see cref="Doctor"/> judges, read from this machine for the selected tenant. <c>tir doctor</c> and the app's status page both use it.</summary>
/// <param name="projectRoots">Folders whose projects are checked too: <c>tir doctor --projects</c>, or the folders the secrets editor scans.</param>
public sealed class MachineProbe(IEnumerable<string>? projectRoots = null) : IDoctorProbe
{
    public MachineProbe(string? projectsRoot)
        : this(projectsRoot is null ? null : [projectsRoot])
    {
    }

    /// <summary>The roots as full paths, without those gone or inside another, so no file is reported twice.</summary>
    readonly string[] roots = Roots(projectRoots ?? []);

    static string[] Roots(IEnumerable<string> folders)
    {
        var full = folders.Select(f => Path.TrimEndingDirectorySeparator(Path.GetFullPath(f))).Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return [.. full.Where(f => !full.Any(o => !string.Equals(o, f, StringComparison.OrdinalIgnoreCase)
            && f.StartsWith(o + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))];
    }

    public bool Enrolled => KeyringStore.Broker is not null;
    public bool Solo => KeyringStore.Tenant is { Solo: true };
    public bool HasDeviceKey => KeyringStore.HasDeviceKey;
    public bool RecoveryKeySet => KeyringStore.Settings.RecoveryPublicKey is not null;

    public DoctorVault? Vault
    {
        get
        {
            var path = KeyringStore.Settings.VaultPath;
            if (!File.Exists(path))
                return null;
            var secrets = VaultFile.Load(path).Secrets;
            return new(secrets.Count,
                secrets.Where(s => !s.WrappedDeks.ContainsKey("hello")).Select(s => s.Slug).ToArray(),
                secrets.Where(s => !s.WrappedDeks.ContainsKey("recovery")).Select(s => s.Slug).ToArray(),
                secrets.Where(s => s.PolicyHash is null).Select(s => s.Slug).ToArray());
        }
    }

    public async Task<int?> BrokerStatusAsync()
    {
        if (KeyringStore.Broker is not { } broker)
            return null;
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            using var response = await http.PostAsync(new Uri(broker.Url, "/lease/heartbeat"), null);
            return (int)response.StatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }

    public async Task<bool> ForwarderListeningAsync()
    {
        using var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync("127.0.0.1", 7781).WaitAsync(TimeSpan.FromSeconds(2));
            return true;
        }
        catch (Exception e) when (e is SocketException or TimeoutException)
        {
            return false;
        }
    }

    public IEnumerable<DoctorFile> UserSecretsFiles()
    {
        // %APPDATA%\Microsoft\UserSecrets\<id>\secrets.json: the root is two levels up from any id's file.
        var root = Path.GetDirectoryName(Path.GetDirectoryName(PathHelper.GetSecretsPathFromSecretsId("x")));
        if (root is null || !Directory.Exists(root))
            return [];
        return Directory.EnumerateFiles(root, SecretsFile.FileName, SearchOption.AllDirectories).Select(Read);
    }

    public IReadOnlyList<string> ExposedVariables =>
        [.. EnvironmentStore.UserVariables().Where(v => v.LooksSecret).Select(v => v.Name)];

    public IEnumerable<DoctorFile> Projects() => Found.Projects.Select(Read);

    public IEnumerable<DoctorFile> ConfigFiles() => Found.Configs.Select(Read);

    public IEnumerable<string> KeyFiles() => Found.Keys.Concat(Found.Pems.Where(HoldsPemPrivateKey));

    public IEnumerable<DoctorFile> GitConfigs() => Found.Repositories.Select(Read).Where(f => f.Text is not null);

    public DoctorGitCredentials? GitCredentials
    {
        get
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return DoctorGitCredentials.From(Read(Path.Combine(profile, ".gitconfig")).Text, Read(Path.Combine(profile, ".git-credentials")).Text);
        }
    }

    public IEnumerable<DoctorToolFile> ToolFiles()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var own = NuGetConfig.Files(null, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData))
            .Append(Path.Combine(profile, ".npmrc")).Append(Path.Combine(profile, ".pypirc")).Where(File.Exists).ToArray();
        return own.Select(path => (Path: path, InProfile: true))
            .Concat(Found.Tools.Where(path => !own.Contains(path, StringComparer.OrdinalIgnoreCase)).Select(path => (Path: path, InProfile: false)))
            .Select(f => new DoctorToolFile(f.Path, Read(f.Path).Text, f.InProfile));
    }

    public IReadOnlyCollection<string> UserVariableNames => [.. EnvironmentStore.UserVariables().Select(v => v.Name)];

    public IEnumerable<DoctorRavenCertificate> RavenCertificates() => RavenCertificateStore.ForVault();

    /// <summary>The unlocked key, for the checks that need the sealed environment's names; <c>null</c> skips them. Never prompts.</summary>
    public IKeyWrapper? Hello { get; init; }

    /// <summary>Opening the environment decrypts its values too; only names leave this property.</summary>
    public DoctorEnvironment? SealedEnvironment
    {
        get
        {
            if (Hello is null)
                return null;
            var environment = EnvironmentStore.Open(Hello).Environment;
            var services = VaultEditor.Load().Services.Where(PlaceholderMinter.CanStandIn).Select(s => new DoctorService(s.Slug, s.Upstream.Host)).ToArray();
            return new([.. environment.Global.Select(v => v.Name).Where(n => environment.PlaceholderFor(n) is null)], services);
        }
    }

    public IEnumerable<InstalledExtension> Extensions() => SurfaceProbe.Extensions();

    public IEnumerable<StartupEntry> StartupEntries() => SurfaceProbe.StartupEntries();

    public IEnumerable<CredentialUse> CredentialUses() => SurfaceProbe.CredentialUses();

    public IEnumerable<UninstallEntry> UninstallEntries() => SurfaceProbe.UninstallEntries();

    public IEnumerable<string> BlockedPrograms() => SurfaceProbe.BlockedPrograms();

    public IEnumerable<ProgramRun> ProgramRuns() => SurfaceProbe.ProgramRuns();

    /// <summary>Where each tool keeps them, honouring <c>GH_CONFIG_DIR</c> and <c>AZURE_CONFIG_DIR</c> as the tools do.</summary>
    public DoctorCliConfigs CliConfigs
    {
        get
        {
            var gh = Environment.GetEnvironmentVariable("GH_CONFIG_DIR") is { Length: > 0 } ghDir ? ghDir
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GitHub CLI");
            var az = Environment.GetEnvironmentVariable("AZURE_CONFIG_DIR") is { Length: > 0 } azDir ? azDir
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".azure");
            return new(Existing(Path.Combine(gh, "hosts.yml")), Existing(Path.Combine(az, "azureProfile.json")));

            static DoctorFile? Existing(string path) => File.Exists(path) ? Read(path) : null;
        }
    }

    public string? GitHubAppService => VaultEditor.Load().Services.FirstOrDefault(ExecPlan.IsGitHubApp)?.Slug;

    /// <summary>How long the walk of the project roots took and what it covered; <c>null</c> until a check needed it.</summary>
    public ScanStats? Scan => found?.Stats;

    public sealed record ScanStats(TimeSpan Elapsed, int Folders, int Files);

    sealed record FoundFiles(List<string> Projects, List<string> Configs, List<string> Keys, List<string> Pems, List<string> Tools, List<string> Repositories, ScanStats Stats);

    FoundFiles? found;
    FoundFiles Found => found ??= Walk();

    static readonly string[] Patterns = ["*.csproj", "appsettings*.json", "*.pfx", "*.p12", "*.pem", "*.key", "nuget.config", ".npmrc"];

    /// <summary>
    /// One walk of the project roots for every file a check reads. Build output, packages and git
    /// internals are never entered: they only copy what is found elsewhere, and on a drive full of
    /// repositories they are half the folders.
    /// </summary>
    FoundFiles Walk()
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        List<string> projects = [], configs = [], keys = [], pems = [], tools = [], repositories = [];
        var folders = roots.Length;
        // Not Hidden: Git for Windows hides .git. ReparsePoint: a junction can't loop the walk.
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System };
        foreach (var root in roots)
        {
            var files = new FileSystemEnumerable<string>(root, (ref FileSystemEntry entry) => entry.ToFullPath(), options)
            {
                ShouldRecursePredicate = (ref FileSystemEntry entry) =>
                {
                    if (entry.FileName is ".git")
                        repositories.Add(Path.Combine(entry.ToFullPath(), "config"));
                    if (entry.FileName is "bin" or "obj" or "node_modules" or ".git")
                        return false;
                    folders++;
                    return true;
                },
                ShouldIncludePredicate = (ref FileSystemEntry entry) => !entry.IsDirectory && Wanted(entry.FileName.ToString()),
            };
            foreach (var path in files)
            {
                var name = Path.GetFileName(path);
                if (Matches("*.csproj", name))
                    projects.Add(path);
                else if (Matches("appsettings*.json", name))
                    configs.Add(path);
                else if (Matches("*.pfx", name) || Matches("*.p12", name))
                    keys.Add(path);
                else if (Matches("nuget.config", name) || Matches(".npmrc", name))
                    tools.Add(path);
                else
                    pems.Add(path);
            }
        }
        return new(projects, configs, keys, pems, tools, repositories, new(clock.Elapsed, folders, projects.Count + configs.Count + keys.Count + pems.Count + tools.Count));
    }

    static bool Wanted(string name) => Patterns.Any(p => Matches(p, name));

    static bool Matches(string pattern, string name) => FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: true);

    /// <summary>Whether a PEM file holds a private key: only its header lines are looked at, and nothing is kept.</summary>
    static bool HoldsPemPrivateKey(string path)
    {
        try
        {
            return File.ReadLines(path).Take(200).Any(line => line.StartsWith("-----BEGIN", StringComparison.Ordinal) && line.Contains("PRIVATE KEY", StringComparison.Ordinal));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    static DoctorFile Read(string path)
    {
        try
        {
            return new(path, File.ReadAllText(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new(path, null);
        }
    }
}
