using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32;
using NSec.Cryptography;
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
    static string EnrollmentJournal => Path.Combine(StateFolder, "enrollments.jsonl");

    // SCM owns the service key. Its presence also distinguishes an older or unfinished install from an unenrolled workstation.
    const string RegistryPath = @"SYSTEM\CurrentControlSet\Services\" + BrokerServiceLayout.Name;
    const string EnrollmentValue = "TiresiasEnrollment";
    const string RemoteTenantsKey = "EnrolledTenants";

    static BrokerEnrollment? ReadEnrollment(RegistryKey? service)
    {
        if (service is null)
            return null;
        if (service.GetValue(EnrollmentValue) is not string value)
            throw new InvalidOperationException("The broker service enrollment is incomplete. Uninstall the service and install it again from the enrolling account.");
        var enrollment = BrokerEnrollment.Read(value);
        using var identity = WindowsIdentity.GetCurrent();
        return enrollment.OwnerSid == identity.User?.Value ? enrollment : null;
    }

    public static TenantConfig? EnrollmentForCurrentUser()
    {
        using var service = UserMachine.LocalMachine?.OpenSubKey(RegistryPath);
        return ReadEnrollment(service)?.Service;
    }

    public static async Task<IReadOnlyList<string>?> ReadJournalAsync() =>
        EnrollmentForCurrentUser() is null ? null : await BrokerJournal.ReadAsync().ConfigureAwait(false);

    internal static (TenantConfig Tenant, bool Service) RequireRecipient(TenantConfig selected)
    {
        using var service = UserMachine.LocalMachine?.OpenSubKey(RegistryPath);
        if (ReadEnrollment(service) is not { } enrollment)
            return (selected, false);
        using var others = service!.OpenSubKey(RemoteTenantsKey);
        var remote = others?.GetValue(selected.Name) is string record ? JsonSerializer.Deserialize<TenantConfig>(record, JsonSerializerOptions.Web) : null;
        return (enrollment.Require(selected, remote), selected.Name == enrollment.Service.Name);
    }

    /// <summary>Records an explicitly enrolled remote tenant alongside the service owner's local enrollment.</summary>
    public static void EnrollRemote(TenantConfig tenant)
    {
        if (EnrollmentForCurrentUser() is not { } installed)
            return;
        if (tenant.Name == installed.Name)
            throw new InvalidOperationException("Uninstall the solo broker service before replacing its tenant.");
        RequireElevated();
        using var service = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: true)
            ?? throw new InvalidOperationException("The broker service is no longer installed.");
        using var owner = WindowsIdentity.GetCurrent();
        BrokerEnrollment.Apply(EnrollmentJournal, owner.User!.Value, "enroll-remote", tenant, () =>
        {
            using var others = service.CreateSubKey(RemoteTenantsKey);
            others.SetValue(tenant.Name, JsonSerializer.Serialize(tenant, JsonSerializerOptions.Web), RegistryValueKind.String);
        });
    }

    public static BrokerServiceState State()
    {
        var service = AdminService.Query(BrokerServiceLayout.Name);
        return !service.Exists ? BrokerServiceState.NotInstalled
            : service.Running ? BrokerServiceState.Running
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
        if (ProfileAccess.Run(() => KeyringStore.Tenant) is not { Solo: true, GenesisHash: { } genesis } tenant)
            throw new InvalidOperationException("Set up solo mode first: tir solo init.");
        if (State() != BrokerServiceState.NotInstalled)
            throw new InvalidOperationException("The Tiresias service is already installed.");
        if (await SoloBroker.ReachableAsync())
            throw new InvalidOperationException("Quit the Tiresias app (and tir agent) first: the broker it hosts holds port 7780.");
        var chain = ProfileAccess.Run(() => TrustLinkJson.ParseChain(File.ReadAllBytes(SoloBroker.TrustChainPath)));
        if (chain is null || !TrustChainVerifier.Verify(chain, genesis).IsValid)
            throw new InvalidOperationException("The solo trust chain doesn't verify against the genesis this device pinned; set solo mode up again.");
        using var owner = WindowsIdentity.GetCurrent();
        var ownerSid = owner.User!.Value;
        using var hello = HelloKeyWrapper.Open(create: false);
        using var revisionKey = hello.RevisionKey();
        var revisionPublicKey = Convert.ToBase64String(revisionKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        // As for the admin tier: a link-safe copy from the user's folder, and state folders that only
        // SYSTEM and Administrators own (one a user made first is moved aside, its owner could reopen it).
        AdminTierSetup.Retry(() => AdminTierSetup.CopyFiles(AppContext.BaseDirectory, BinaryFolder));
        foreach (var folder in BrokerServiceLayout.SecuredFolders(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)))
            AdminTierSetup.Secure(folder);
        File.WriteAllBytes(BrokerServiceLayout.TrustChainPath(StateFolder), TrustLinkJson.WriteChain(chain));
        File.WriteAllBytes(Path.Combine(StateFolder, BrokerServiceConfig.FileName),
            new BrokerServiceConfig(tenant.VaultPath, genesis, TimeZoneInfo.Local.Id, ownerSid, revisionPublicKey).Write());
        var identityFile = Path.Combine(StateFolder, BrokerServiceLayout.IdentityPublicFile);
        File.Delete(identityFile);

        Run("sc.exe", BrokerServiceLayout.CreateArguments(Path.Combine(BinaryFolder, "tir.exe")));
        Run("icacls.exe", BrokerServiceLayout.StateFolderAcl(StateFolder));
        // Precreate the journal so an empty history is readable before the first broker decision.
        using (File.Open(BrokerServiceLayout.AuditPath(StateFolder, ownerSid), FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read)) { }
        ProfileAccess.Run(() => BrokerVaultAccess.Set(tenant.VaultPath, new NTAccount(BrokerServiceLayout.Account), grant: true));
        Run("sc.exe", ["start", BrokerServiceLayout.Name]);

        for (var i = 0; i < 60 && !File.Exists(identityFile); i++)
            await Task.Delay(500);
        if (!File.Exists(identityFile))
            throw new InvalidOperationException("The Tiresias service didn't start within 30 seconds. See the Application log in Event Viewer.");
        var recipient = tenant with { Url = SoloBroker.Url, IdentityKey = File.ReadAllText(identityFile).Trim() };
        KeyringStore.ValidateBrokerKey(recipient.IdentityKey);
        using var registration = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: true)
            ?? throw new InvalidOperationException("The new broker service registration was not found.");
        BrokerEnrollment.Apply(EnrollmentJournal, ownerSid, "install", recipient, () =>
        {
            registration.SetValue(EnrollmentValue, new BrokerEnrollment(ownerSid, recipient).Write(), RegistryValueKind.String);
            ProfileAccess.Run(() => KeyringStore.Enroll(recipient));
        });
    }

    /// <summary>Stops and removes the service and its binaries, gives the trust chain back to the app, and pins the app's identity again. Keeps the state folder (its audit log).</summary>
    public static void Uninstall()
    {
        RequireElevated();
        if (State() == BrokerServiceState.NotInstalled)
            throw new InvalidOperationException("The Tiresias service isn't installed.");
        var serviceConfig = BrokerServiceConfig.Read(File.ReadAllBytes(Path.Combine(StateFolder, BrokerServiceConfig.FileName)));
        using var owner = WindowsIdentity.GetCurrent();
        if (serviceConfig.OwnerSid is { } sid && sid != owner.User!.Value)
            throw new InvalidOperationException("Remove the service from the Windows account that installed it.");
        var tenant = ProfileAccess.Run(() => KeyringStore.Tenant);
        using (var registration = Registry.LocalMachine.OpenSubKey(RegistryPath))
            if (registration?.GetValue(EnrollmentValue) is string)
                tenant = ReadEnrollment(registration)?.Service ?? throw new InvalidOperationException("Remove the service from the Windows account that installed it.");
        // Older or interrupted installs may lack a registered tenant. Restore a profile only when its vault and genesis match.
        if (tenant is not { Solo: true } || tenant.GenesisHash != serviceConfig.GenesisHash ||
            !string.Equals(tenant.VaultPath, serviceConfig.VaultPath, StringComparison.OrdinalIgnoreCase))
            tenant = null;
        BrokerEnrollment.Apply(EnrollmentJournal, owner.User!.Value, "uninstall", tenant, () => RemoveService(serviceConfig, tenant));
        if (Directory.Exists(BinaryFolder) && !IsInside(AppContext.BaseDirectory, BinaryFolder))
            AdminTierSetup.Retry(() => Directory.Delete(BinaryFolder, recursive: true));
    }

    static void RemoveService(BrokerServiceConfig config, TenantConfig? tenant)
    {
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
        ProfileAccess.Run(() => BrokerVaultAccess.Set(config.VaultPath, new NTAccount(BrokerServiceLayout.Account), grant: false));
        // The service may have extended the chain (tir trust bind-hello); the app's broker carries on from there.
        var served = BrokerServiceLayout.TrustChainPath(StateFolder);
        if (tenant is { Solo: true, GenesisHash: { } genesis })
        {
            var chain = File.Exists(served) ? TrustLinkJson.ParseChain(File.ReadAllBytes(served)) : null;
            ProfileAccess.Run(() =>
            {
                if (chain is not null && TrustChainVerifier.Verify(chain, genesis).IsValid)
                {
                    File.WriteAllBytes(SoloBroker.TrustChainPath, TrustLinkJson.WriteChain(chain));
                    File.Delete(SoloBroker.TrustChainPath + ".head");
                }
                KeyringStore.Enroll(tenant with { Url = SoloBroker.Url, IdentityKey = SoloBroker.IdentityPublicKey() });
            });
        }
        Run("sc.exe", ["delete", BrokerServiceLayout.Name]);
    }

    /// <summary>The service's body: the solo broker under the service manager, with its state in the service's own folder.</summary>
    public static async Task RunAsync()
    {
        var config = BrokerServiceConfig.Read(File.ReadAllBytes(Path.Combine(StateFolder, BrokerServiceConfig.FileName)));
        var settings = BrokerServiceLayout.BrokerSettings(StateFolder, config);
        File.WriteAllText(Path.Combine(StateFolder, BrokerServiceLayout.IdentityPublicFile), SoloBroker.IdentityPublicKey(settings["Broker:IdentityKeyPath"]!));
        var contentRoot = Directory.CreateDirectory(Path.Combine(StateFolder, "content")).FullName;
        await using var broker = new SoloBroker();
        await broker.StartAsync(config.VaultPath, contentRoot, settings, windowsService: true, journalReaderSid: config.OwnerSid);
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
