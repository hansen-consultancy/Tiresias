using System.Net.Sockets;
using Tiresias.Client;
using Tiresias.Protocol;
using Tiresias.Vault;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace Tiresias.Keyring;

/// <summary><c>tir doctor</c>: gathers facts from this machine and prints <see cref="Doctor"/>'s verdicts. Exit 1 on any failure.</summary>
static class DoctorCommand
{
    public static async Task<int> RunAsync(CommandLine args)
    {
        var checks = await Doctor.RunAsync(new MachineProbe(args.Option("--projects")));
        foreach (var check in checks)
            Console.WriteLine($"{check.Status switch { DoctorStatus.Ok => "ok  ", DoctorStatus.Warn => "WARN", _ => "FAIL" }}  {check.Name}: {check.Detail}");
        return checks.Any(c => c.Status == DoctorStatus.Fail) ? 1 : 0;
    }

    sealed class MachineProbe(string? projectsRoot) : IDoctorProbe
    {
        public bool Enrolled => KeyringStore.Broker is not null;
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
                    secrets.Where(s => !s.WrappedDeks.ContainsKey("recovery")).Select(s => s.Slug).ToArray());
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

        public IEnumerable<DoctorFile> Projects()
        {
            if (projectsRoot is null)
                return [];
            return Directory.EnumerateFiles(projectsRoot, "*.csproj", SearchOption.AllDirectories)
                .Where(p => !p.Split(Path.DirectorySeparatorChar).Any(d => d is "bin" or "obj" or "node_modules"))
                .Select(Read);
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
}
