using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSec.Cryptography;
using Tiresias.Broker;
using Tiresias.Client;
using Tiresias.Trust;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// Solo mode's broker: the same broker code as a hosted one, on loopback. It identifies the calling
/// process from the loopback connection, so no forwarder is needed. It runs inside the agent unless
/// the Windows service is installed (<see cref="BrokerService"/>, docs/broker-service.md), which
/// hosts this same class under its own account; <c>tir doctor</c> says which.
/// </summary>
/// <remarks>
/// The vault can change while the broker runs (<c>tir service add</c>, <c>tir vault add</c>, the
/// app's Services window). Before each request the broker checks the file's timestamp and, when it
/// moved, swaps the new vault in without ending the lease (<see cref="BrokerState.ReplaceVault"/>).
/// Secrets of the open lease left without a DEK are handed to <see cref="SecretsUnleased"/>, which
/// the agent answers by sealing them to the lease, before the request goes on. A vault that doesn't
/// load is reported on <see cref="Log"/> and the broker keeps the one it had.
/// </remarks>
public sealed class SoloBroker : IAsyncDisposable
{
    public static readonly Uri Url = new("http://127.0.0.1:7780");

    WebApplication? app;
    readonly Lock vaultGate = new();
    readonly SemaphoreSlim sealing = new(1, 1);
    DateTime vaultStamp;
    IReadOnlyList<string> unleased = [];

    /// <summary>One line per vault reload, or why one failed. Never a value.</summary>
    public event Action<string>? Log;

    /// <summary>
    /// Called with the open lease's secrets that have no DEK after a reload (a secret just added or
    /// re-sealed). The agent seals them to the lease, if it is unlocked; the request that noticed
    /// the change waits for it, so it already sees the new secret.
    /// </summary>
    public Func<IReadOnlyList<string>, Task>? SecretsUnleased { get; set; }

    public static string Directory => Path.Combine(KeyringStore.Directory, "solo");
    public static string AuditPath => Path.Combine(Directory, "audit.jsonl");
    public static string IdentityKeyPath => Path.Combine(Directory, "identity.key");
    public static string TrustChainPath => Path.Combine(Directory, "trust-chain.json");

    public bool Running => app is not null;

    /// <summary>Starts the broker for the solo tenant, creating an empty vault when there is none yet.</summary>
    /// <exception cref="IOException">Port 7780 is taken by another program.</exception>
    public Task StartAsync()
    {
        if (app is not null)
            return Task.CompletedTask;
        var tenant = KeyringStore.Tenant is { Solo: true } t ? t : throw new InvalidOperationException("Solo mode isn't set up on this device.");
        if (!File.Exists(tenant.VaultPath))
            VaultFile.Save(tenant.VaultPath, new VaultDocument([], []));
        return StartAsync(tenant.VaultPath, Directory, new Dictionary<string, string?>
        {
            ["Broker:VaultPath"] = tenant.VaultPath,
            ["Broker:AuditPath"] = AuditPath,
            ["Broker:IdentityKeyPath"] = IdentityKeyPath,
            ["Broker:TrustChainPath"] = TrustChainPath,
            ["Broker:PinnedGenesisHash"] = tenant.GenesisHash,
            ["Broker:TimeZone"] = TimeZoneInfo.Local.Id,
            ["Broker:IdentifyLoopbackCaller"] = "true",
        });
    }

    /// <param name="contentRoot">An empty folder of its own, so no appsettings.json from wherever tir was started is read.</param>
    /// <param name="windowsService">Run under the service manager (<see cref="BrokerService"/>).</param>
    /// <param name="journalReaderSid">The installing account recorded in the service's protected configuration.</param>
    internal async Task StartAsync(string vaultPath, string contentRoot, Dictionary<string, string?> settings, bool windowsService = false, string? journalReaderSid = null)
    {
        vaultStamp = File.GetLastWriteTimeUtc(vaultPath);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [],
            ContentRootPath = contentRoot,
            EnvironmentName = "Production",
        });
        builder.Configuration.AddInMemoryCollection(settings);
        builder.WebHost.UseUrls(Url.GetLeftPart(UriPartial.Authority));
        builder.Logging.ClearProviders();
        if (windowsService)
        {
            builder.Host.UseWindowsService(o => o.ServiceName = BrokerServiceLayout.Name);
            if (journalReaderSid is not null)
                builder.Services.AddHostedService(sp => new BrokerJournal(sp.GetRequiredService<Tiresias.Audit.AuditLog>(), journalReaderSid));
        }

        var built = BrokerHost.Build(builder);
        var state = built.Services.GetRequiredService<BrokerState>();
        built.Use(async (context, next) =>
        {
            await KeepVaultCurrentAsync(state, vaultPath, context.Request.Path);
            await next(context);
        });
        try
        {
            await built.StartAsync();
        }
        catch (Exception e) when (e is IOException or SocketException)
        {
            await built.DisposeAsync();
            throw new IOException($"The solo broker can't listen on {Url}: another program is using port {Url.Port}.", e);
        }
        app = built;
    }

    /// <summary>Waits until the host is told to stop, as the service manager does.</summary>
    internal Task WaitForShutdownAsync() => app?.WaitForShutdownAsync() ?? Task.CompletedTask;

    public async Task StopAsync()
    {
        if (Interlocked.Exchange(ref app, null) is not { } running)
            return;
        await running.StopAsync();
        await running.DisposeAsync();
    }

    async Task KeepVaultCurrentAsync(BrokerState state, string vaultPath, PathString path)
    {
        ReloadIfChanged(state, vaultPath);
        // The agent's own sealing (and an unlock) goes through /lease; those requests must not wait for it.
        if (path.StartsWithSegments("/lease", StringComparison.Ordinal) || SecretsUnleased is not { } seal)
            return;
        if (Volatile.Read(ref unleased).Count == 0)
            return;
        await sealing.WaitAsync();
        try
        {
            var slugs = Interlocked.Exchange(ref unleased, []);
            if (slugs.Count > 0)
                await seal(slugs);
        }
        finally
        {
            sealing.Release();
        }
    }

    void ReloadIfChanged(BrokerState state, string vaultPath)
    {
        lock (vaultGate)
        {
            var stamp = File.GetLastWriteTimeUtc(vaultPath);
            if (stamp == vaultStamp)
                return;
            VaultDocument vault;
            try
            {
                vault = VaultFile.Load(vaultPath);
            }
            catch (IOException)
            {
                // Mid-write or held open: try again at the next request.
                return;
            }
            catch (Exception e) when (e is JsonException or InvalidDataException or ArgumentException or UnauthorizedAccessException or NotSupportedException)
            {
                vaultStamp = stamp;
                Log?.Invoke($"The vault changed but can't be read ({e.Message}). The solo broker keeps using the services and secrets it had; fix {vaultPath} or undo the change.");
                return;
            }
            vaultStamp = stamp;
            var reload = state.ReplaceVault(vault);
            if (reload.RolledBack is { Count: > 0 } rolledBack)
            {
                Log?.Invoke($"The vault holds older versions of {string.Join(", ", rolledBack)} than this lease already saw, as when an older copy is restored. The solo broker keeps the vault it had; undo the change in {vaultPath}.");
                return;
            }
            if (reload.Refused)
            {
                Log?.Invoke($"The vault changed the services of {string.Join(", ", reload.Unapproved)} without your approval. The solo broker keeps the services it had; undo the change in {vaultPath}.");
                return;
            }
            Volatile.Write(ref unleased, reload.Unleased);
            Log?.Invoke($"Vault reloaded: {vault.Services.Count} service(s), {vault.Secrets.Count} secret(s).");
        }
    }

    /// <summary>The broker identity's public key (base64), creating the identity on first use. The Keyring pins it.</summary>
    public static string IdentityPublicKey() => IdentityPublicKey(IdentityKeyPath);

    internal static string IdentityPublicKey(string identityKeyPath)
    {
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(identityKeyPath)!);
        using var key = BrokerIdentity.LoadOrCreate(IdentityKeyStore.ForPlatform(identityKeyPath, NullLogger.Instance), NullLogger.Instance);
        return Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>
    /// Sets up solo mode: a trust chain whose genesis this device (device key and Hello key, one Hello
    /// prompt) and the paper key sign, the broker identity, and the Keyring enrolled with that broker. <paramref name="recoveryKey"/> is the
    /// paper key's raw bytes, which must match the recovery key already stored.
    /// </summary>
    /// <exception cref="InvalidOperationException">Already enrolled, no recovery key yet, or the key typed isn't it.</exception>
    public static void Setup(ReadOnlySpan<byte> recoveryKey)
    {
        if (KeyringStore.Tenants.Count > 0)
            throw new InvalidOperationException(KeyringStore.Tenant is { Solo: true }
                ? "Solo mode is already set up on this device."
                : "This device is already enrolled with a broker; solo mode is for a device without one.");
        var settings = KeyringStore.Settings;
        if (RecoveryKey.PublicKey is not { } recoveryPublic)
            throw new InvalidOperationException("Enroll the recovery key before setting up the solo broker.");
        if (!PaperKey.Matches(recoveryKey, Convert.FromBase64String(recoveryPublic)))
            throw new InvalidOperationException("That is not the recovery key this device stored. Check the words you wrote down.");

        System.IO.Directory.CreateDirectory(Directory);
        using var deviceKey = KeyringStore.LoadOrCreateDeviceKey();
        using var paperKey = PaperKey.SigningKey(recoveryKey);
        var genesis = TrustChain.Start("solo", "owner", new Signer(settings.DeviceId, deviceKey, HelloKeyWrapper.LinkKey(create: true)), new Signer("paper", paperKey),
            new TrustPolicy(), DateTimeOffset.UtcNow);
        File.WriteAllBytes(TrustChainPath, TrustLinkJson.WriteChain([genesis]));
        File.Delete(TrustChainPath + ".head");

        if (!File.Exists(settings.VaultPath))
            VaultFile.Save(settings.VaultPath, new VaultDocument([], []));
        KeyringStore.Enroll(new(KeyringStore.DefaultTenant, Url, IdentityPublicKey(), settings.VaultPath, TrustChain.Hash(genesis), Solo: true));
    }

    /// <summary>Whether something answers on the solo broker's port right now (the app or <c>tir agent</c> hosting it).</summary>
    public static async Task<bool> ReachableAsync()
    {
        using var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(IPAddress.Loopback, Url.Port).WaitAsync(TimeSpan.FromSeconds(1));
            return true;
        }
        catch (Exception e) when (e is SocketException or TimeoutException)
        {
            return false;
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
