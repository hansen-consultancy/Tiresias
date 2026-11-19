using System.Net.Sockets;
using Tiresias.Client;
using Tiresias.Protocol;
using Tiresias.Vault;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace Tiresias.Agent;

/// <summary>The facts <see cref="Doctor"/> judges, read from this machine for the selected tenant. <c>tir doctor</c> and the app's status page both use it.</summary>
public sealed class MachineProbe(string? projectsRoot = null) : IDoctorProbe
{
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

    public IEnumerable<DoctorFile> Projects() => Under("*.csproj").Select(Read);

    public IEnumerable<DoctorFile> ConfigFiles() => Under("appsettings*.json").Select(Read);

    public IEnumerable<string> KeyFiles() =>
        Under("*.pfx").Concat(Under("*.p12")).Concat(Under("*.pem").Concat(Under("*.key")).Where(HoldsPemPrivateKey));

    /// <summary>Files under the projects root, skipping build output and packages, which only copy what is already found.</summary>
    IEnumerable<string> Under(string pattern) => projectsRoot is null
        ? []
        : Directory.EnumerateFiles(projectsRoot, pattern, new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
            .Where(p => !p.Split(Path.DirectorySeparatorChar).Any(d => d is "bin" or "obj" or "node_modules" or ".git"));

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
