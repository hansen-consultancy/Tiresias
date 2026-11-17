using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSec.Cryptography;
using Tiresias.Broker;
using Tiresias.Client;
using Tiresias.Trust;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// Solo mode's broker: the same broker code as a hosted one, run inside the agent on loopback. It
/// identifies the calling process from the loopback connection, so no forwarder is needed. The
/// design's target is a Windows service under its own virtual account (processes running as the
/// user then can't read its memory); until that is built, the broker shares the agent's process
/// and <c>tir doctor</c> says so.
/// </summary>
/// <remarks>
/// The broker loads the vault when it starts, so a vault changed since (a secret added) is picked
/// up by <see cref="RefreshAsync"/>, which the agent calls before every unlock.
/// </remarks>
public sealed class SoloBroker : IAsyncDisposable
{
    public static readonly Uri Url = new("http://127.0.0.1:7780");

    WebApplication? app;
    DateTime vaultStamp;

    public static string Directory => Path.Combine(KeyringStore.Directory, "solo");
    public static string AuditPath => Path.Combine(Directory, "audit.jsonl");
    public static string IdentityKeyPath => Path.Combine(Directory, "identity.key");
    public static string TrustChainPath => Path.Combine(Directory, "trust-chain.json");

    public bool Running => app is not null;

    /// <summary>Starts the broker for the solo tenant, creating an empty vault when there is none yet.</summary>
    /// <exception cref="IOException">Port 7780 is taken by another program.</exception>
    public async Task StartAsync()
    {
        if (app is not null)
            return;
        var tenant = KeyringStore.Tenant is { Solo: true } t ? t : throw new InvalidOperationException("Solo mode isn't set up on this device.");
        if (!File.Exists(tenant.VaultPath))
            VaultFile.Save(tenant.VaultPath, new VaultDocument([], []));
        vaultStamp = File.GetLastWriteTimeUtc(tenant.VaultPath);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [],
            // An empty folder of its own, so no appsettings.json from wherever tir was started is read.
            ContentRootPath = Directory,
            EnvironmentName = "Production",
        });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Broker:VaultPath"] = tenant.VaultPath,
            ["Broker:AuditPath"] = AuditPath,
            ["Broker:IdentityKeyPath"] = IdentityKeyPath,
            ["Broker:TrustChainPath"] = TrustChainPath,
            ["Broker:PinnedGenesisHash"] = tenant.GenesisHash,
            ["Broker:TimeZone"] = TimeZoneInfo.Local.Id,
            ["Broker:IdentifyLoopbackCaller"] = "true",
        });
        builder.WebHost.UseUrls(Url.GetLeftPart(UriPartial.Authority));
        builder.Logging.ClearProviders();

        var built = BrokerHost.Build(builder);
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

    public async Task StopAsync()
    {
        if (Interlocked.Exchange(ref app, null) is not { } running)
            return;
        await running.StopAsync();
        await running.DisposeAsync();
    }

    /// <summary>Restarts the broker when the vault changed since it started, so new secrets can be leased.</summary>
    public async Task RefreshAsync()
    {
        if (app is null || KeyringStore.Tenant is not { Solo: true } tenant)
            return;
        if (File.GetLastWriteTimeUtc(tenant.VaultPath) == vaultStamp)
            return;
        await StopAsync();
        await StartAsync();
    }

    /// <summary>The broker identity's public key (base64), creating the identity on first use. The Keyring pins it.</summary>
    public static string IdentityPublicKey()
    {
        System.IO.Directory.CreateDirectory(Directory);
        using var key = BrokerIdentity.LoadOrCreate(IdentityKeyStore.ForPlatform(IdentityKeyPath, NullLogger.Instance), NullLogger.Instance);
        return Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>
    /// Sets up solo mode: a trust chain whose genesis this device and the paper key sign, the broker
    /// identity, and the Keyring enrolled with that broker. <paramref name="recoveryKey"/> is the
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
        if (settings.RecoveryPublicKey is not { } recoveryPublic)
            throw new InvalidOperationException("Create the recovery key first.");
        if (!PaperKey.Matches(recoveryKey, Convert.FromBase64String(recoveryPublic)))
            throw new InvalidOperationException("That is not the recovery key this device stored. Check the words you wrote down.");

        System.IO.Directory.CreateDirectory(Directory);
        using var deviceKey = KeyringStore.LoadOrCreateDeviceKey();
        using var paperKey = PaperKey.SigningKey(recoveryKey);
        var genesis = TrustChain.Start("solo", "owner", new Signer(settings.DeviceId, deviceKey), new Signer("paper", paperKey),
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
