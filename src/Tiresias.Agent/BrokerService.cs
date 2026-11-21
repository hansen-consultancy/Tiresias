using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using Tiresias.Client;
using Tiresias.Trust;

namespace Tiresias.Agent;

/// <summary>
/// Solo mode's broker as the <c>Tiresias</c> Windows service under its own virtual account, so
/// programs running as the user can't read its memory or write the files it trusts
/// (docs/broker-service.md). Install and uninstall need an elevated <c>tir</c>; the service manager
/// starts <see cref="RunAsync"/>.
/// </summary>
public static class BrokerService
{
    static string BinaryFolder => BrokerServiceLayout.BinaryFolder(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    static string StateFolder => BrokerServiceLayout.StateFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

    public static BrokerServiceState State()
    {
        using var service = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == BrokerServiceLayout.Name);
        return service is null ? BrokerServiceState.NotInstalled
            : service.Status == ServiceControllerStatus.Running ? BrokerServiceState.Running
            : BrokerServiceState.Stopped;
    }

    /// <summary>
    /// Copies this <c>tir</c> to Program Files, gives the service its state folder with the trust
    /// chain, registers and starts it, and pins the Keyring to the service's identity.
    /// </summary>
    /// <exception cref="InvalidOperationException">Not elevated, solo mode not set up, already installed, or the app still hosts the broker.</exception>
    public static async Task InstallAsync()
    {
        RequireElevated();
        if (KeyringStore.Tenant is not { Solo: true, GenesisHash: { } genesis } tenant)
            throw new InvalidOperationException("Set up solo mode first: tir solo init.");
        if (State() != BrokerServiceState.NotInstalled)
            throw new InvalidOperationException("The Tiresias service is already installed.");
        if (await SoloBroker.ReachableAsync())
            throw new InvalidOperationException("Quit the Tiresias app (and tir agent) first: the broker it hosts holds port 7780.");
        var chain = TrustLinkJson.ParseChain(File.ReadAllBytes(SoloBroker.TrustChainPath));
        if (chain is null || !TrustChainVerifier.Verify(chain, genesis).IsValid)
            throw new InvalidOperationException("The solo trust chain doesn't verify against the genesis this device pinned; set solo mode up again.");

        // As for the admin tier: a link-safe copy from the user's folder, and state folders that only
        // SYSTEM and Administrators own (one a user made first is moved aside, its owner could reopen it).
        AdminTierSetup.Retry(() => AdminTierSetup.CopyFiles(AppContext.BaseDirectory, BinaryFolder));
        foreach (var folder in BrokerServiceLayout.SecuredFolders(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)))
            AdminTierSetup.Secure(folder);
        File.WriteAllBytes(BrokerServiceLayout.TrustChainPath(StateFolder), TrustLinkJson.WriteChain(chain));
        File.WriteAllBytes(Path.Combine(StateFolder, BrokerServiceConfig.FileName),
            new BrokerServiceConfig(tenant.VaultPath, genesis, TimeZoneInfo.Local.Id).Write());
        var identityFile = Path.Combine(StateFolder, BrokerServiceLayout.IdentityPublicFile);
        File.Delete(identityFile);

        Run("sc.exe", BrokerServiceLayout.CreateArguments(Path.Combine(BinaryFolder, "tir.exe")));
        Run("icacls.exe", BrokerServiceLayout.StateFolderAcl(StateFolder));
        Run("icacls.exe", BrokerServiceLayout.VaultFolderAcl(Path.GetDirectoryName(Path.GetFullPath(tenant.VaultPath))!));
        Run("sc.exe", ["start", BrokerServiceLayout.Name]);

        for (var i = 0; i < 60 && !File.Exists(identityFile); i++)
            await Task.Delay(500);
        if (!File.Exists(identityFile))
            throw new InvalidOperationException("The Tiresias service didn't start within 30 seconds. See the Application log in Event Viewer.");
        KeyringStore.Enroll(tenant with { IdentityKey = File.ReadAllText(identityFile).Trim() });
    }

    /// <summary>Stops and removes the service and its binaries, gives the trust chain back to the app, and pins the app's identity again. Keeps the state folder (its audit log).</summary>
    public static void Uninstall()
    {
        RequireElevated();
        if (State() == BrokerServiceState.NotInstalled)
            throw new InvalidOperationException("The Tiresias service isn't installed.");
        // sc stop only asks; the service can't be deleted, nor its binary removed, until it has stopped.
        using (var service = new ServiceController(BrokerServiceLayout.Name))
        {
            if (service.Status != ServiceControllerStatus.Stopped)
            {
                if (service.Status != ServiceControllerStatus.StopPending)
                    service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        }
        Run("sc.exe", ["delete", BrokerServiceLayout.Name]);

        // The service may have extended the chain (tir trust bind-hello); the app's broker carries on from there.
        var served = BrokerServiceLayout.TrustChainPath(StateFolder);
        if (KeyringStore.Tenant is { Solo: true, GenesisHash: { } genesis } tenant)
        {
            if (File.Exists(served) && TrustLinkJson.ParseChain(File.ReadAllBytes(served)) is { } chain && TrustChainVerifier.Verify(chain, genesis).IsValid)
            {
                File.WriteAllBytes(SoloBroker.TrustChainPath, TrustLinkJson.WriteChain(chain));
                File.Delete(SoloBroker.TrustChainPath + ".head");
            }
            KeyringStore.Enroll(tenant with { IdentityKey = SoloBroker.IdentityPublicKey() });
        }
        if (Directory.Exists(BinaryFolder) && !IsInside(AppContext.BaseDirectory, BinaryFolder))
            AdminTierSetup.Retry(() => Directory.Delete(BinaryFolder, recursive: true));
    }

    /// <summary>The service's body: the solo broker under the service manager, with its state in the service's own folder.</summary>
    public static async Task RunAsync()
    {
        var config = BrokerServiceConfig.Read(File.ReadAllBytes(Path.Combine(StateFolder, BrokerServiceConfig.FileName)));
        var settings = BrokerServiceLayout.BrokerSettings(StateFolder, config);
        File.WriteAllText(Path.Combine(StateFolder, BrokerServiceLayout.IdentityPublicFile), SoloBroker.IdentityPublicKey(settings["Broker:IdentityKeyPath"]!));
        var contentRoot = Directory.CreateDirectory(Path.Combine(StateFolder, "content")).FullName;
        await using var broker = new SoloBroker();
        await broker.StartAsync(config.VaultPath, contentRoot, settings, windowsService: true);
        await broker.WaitForShutdownAsync();
    }

    static void RequireElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Run this from a terminal opened as administrator.");
    }

    static void Run(string program, IReadOnlyList<string> arguments, bool check = true)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, program)) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
            info.ArgumentList.Add(argument);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (check && process.ExitCode != 0)
            throw new InvalidOperationException($"{program} {arguments[0]} failed ({process.ExitCode}): {output.Trim()}");
    }

    static bool IsInside(string path, string folder) =>
        Path.GetFullPath(path).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
}
