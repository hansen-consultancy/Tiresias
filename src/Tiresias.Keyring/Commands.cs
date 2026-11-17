using System.Text.Json;
using System.Text.RegularExpressions;
using Tiresias.Access;
using Tiresias.Client;
using Tiresias.Crypto;
using Tiresias.Transport;
using Tiresias.Trust;
using Tiresias.Vault;
using NSec.Cryptography;

namespace Tiresias.Keyring;

/// <summary>The <c>tir</c> commands. Each returns the process exit code.</summary>
static class Commands
{
    const string RecoveryWrapperId = "recovery";

    static readonly Regex Slug = new("^[a-z0-9][a-z0-9-]{0,62}$", RegexOptions.CultureInvariant);

    public static int Enroll(CommandLine args)
    {
        var url = new Uri(args.Require("--broker"));
        var brokerKey = args.Require("--broker-key");
        PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(brokerKey), KeyBlobFormat.RawPublicKey);

        var tenant = args.Option("--tenant") ?? KeyringStore.DefaultTenant;
        var genesis = args.Option("--genesis");
        if (genesis is not null && !Regex.IsMatch(genesis, "^[0-9a-f]{64}$"))
            throw new UsageException("--genesis is the trust chain's genesis hash, 64 lower-case hex digits.");

        var settings = KeyringStore.Settings;
        settings = settings with { DeviceId = args.Option("--device") ?? settings.DeviceId };
        KeyringStore.Settings = settings;
        var vaultPath = args.Option("--vault") is { } vault ? Path.GetFullPath(vault)
            : KeyringStore.Tenants.FirstOrDefault(t => t.Name == tenant)?.VaultPath
            ?? (tenant == KeyringStore.DefaultTenant ? settings.VaultPath : Path.Combine(KeyringStore.Directory, $"vault-{tenant}.json"));
        KeyringStore.Enroll(new(tenant, url, brokerKey, vaultPath, genesis));

        using var device = KeyringStore.LoadOrCreateDeviceKey();
        Console.WriteLine($"Pinned broker {url} for tenant {tenant} (identity {brokerKey}, vault {vaultPath}).");
        Console.WriteLine("Add this device to the broker's configuration:");
        Console.WriteLine($"  \"Broker\": {{ \"Devices\": {{ \"{settings.DeviceId}\": \"{Convert.ToBase64String(device.PublicKey.Export(KeyBlobFormat.RawPublicKey))}\" }} }}");
        return 0;
    }

    public static int RecoveryInit()
    {
        var settings = KeyringStore.Settings;
        if (settings.RecoveryPublicKey is not null)
        {
            Console.Error.WriteLine("A recovery key is already configured. Secrets sealed so far open only with that one; refusing to replace it.");
            return 1;
        }

        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var raw = key.Export(KeyBlobFormat.RawPrivateKey);
        try
        {
            Console.WriteLine("Recovery key. Write it on paper now; it is shown once and stored nowhere:");
            Console.WriteLine();
            Console.WriteLine(Terminal.PaperBase32(raw));
            Console.WriteLine();
        }
        finally
        {
            Array.Clear(raw);
        }
        KeyringStore.Settings = settings with { RecoveryPublicKey = Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)) };
        Console.WriteLine("Stored the public half only. Clear this terminal's scrollback.");
        return 0;
    }

    public static int VaultAdd(CommandLine args)
    {
        var slug = args.Require(2, "slug");
        if (!Slug.IsMatch(slug))
            throw new UsageException("A slug is lower-case letters, digits and dashes.");
        var settings = KeyringStore.Settings;
        if (settings.RecoveryPublicKey is null)
            throw new UsageException("No recovery key yet. Run tir recovery init first, so no secret depends on the TPM alone.");

        var vault = File.Exists(settings.VaultPath) ? VaultFile.Load(settings.VaultPath) : new VaultDocument([], []);
        var version = (vault.FindSecret(slug)?.Version ?? 0) + 1;

        var value = args.Flag("--from-stdin")
            ? Terminal.ReadStdin()
            : Terminal.ReadHidden($"Value for {slug} (the whole Authorization header, e.g. 'Bearer sk-...'): ");
        SealedSecret secret;
        try
        {
            if (value.Length == 0)
                throw new UsageException("Empty value.");
            using var hello = HelloKeyWrapper.Open(create: true);
            var recovery = X25519KeyWrapper.ForPublicKey(RecoveryWrapperId, Convert.FromBase64String(settings.RecoveryPublicKey));
            secret = SecretEnvelope.Seal(slug, version, value, [hello, recovery]);
        }
        finally
        {
            Array.Clear(value);
        }

        VaultFile.Save(settings.VaultPath, vault with { Secrets = [.. vault.Secrets.Where(s => s.Slug != slug), secret] });
        Console.WriteLine($"Sealed {slug} v{version} into {settings.VaultPath}. Copy that file to the broker's VaultPath and restart the broker.");
        return 0;
    }

    /// <summary>
    /// When the tenant was enrolled with a genesis hash, refuses a broker whose trust chain doesn't
    /// verify per <see cref="BrokerTrust"/>, and remembers the head it accepts so the next unlock
    /// catches a rollback. Returns the reason to refuse, or null.
    /// </summary>
    static async Task<string?> CheckTrustChainAsync(BrokerClient client, BrokerPin broker, KeyringSettings settings)
    {
        if (KeyringStore.Tenant?.GenesisHash is not { } genesis)
            return null;
        var (status, body) = await client.GetAsync("/trust/chain");
        if (status != System.Net.HttpStatusCode.OK)
            return $"This tenant pins a trust chain but the broker served none ({(int)status}).";
        var result = BrokerTrust.Evaluate(TrustLinkJson.ParseChain(body), genesis, KeyringStore.ChainHead,
            Convert.FromBase64String(broker.IdentityKey), settings.DeviceId);
        if (!result.Trusted)
            return result.Error;
        KeyringStore.ChainHead = result.Head;
        return null;
    }

    public static async Task<int> UnlockAsync(CommandLine args)
    {
        var broker = KeyringStore.RequireBroker();
        var settings = KeyringStore.Settings;
        var vault = VaultFile.Load(settings.VaultPath);
        var slugs = args.Option("--secrets") is { } list
            ? list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : vault.Secrets.Where(s => s.WrappedDeks.ContainsKey("hello")).Select(s => s.Slug).ToArray();
        var secrets = slugs.Select(s => vault.FindSecret(s) ?? throw new UsageException($"No secret '{s}' in {settings.VaultPath}.")).ToArray();

        using var client = Client(broker, settings);
        if (await CheckTrustChainAsync(client, broker, settings) is { } untrusted)
            return Fail($"{untrusted} Nothing was sealed.");
        var begin = await client.PostAsync("/lease/begin");
        if (!begin.Ok || begin.Body is not { } body)
            return Fail($"Lease not opened: {begin.Describe()}");

        var offer = new LeaseOffer(
            body.GetProperty("leaseId").GetString()!,
            Convert.FromBase64String(body.GetProperty("leaseKey").GetString()!),
            DateTimeOffset.FromUnixTimeSeconds(body.GetProperty("hardCapAt").GetInt64()));
        var identity = PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(broker.IdentityKey), KeyBlobFormat.RawPublicKey);
        if (!offer.Verify(identity, Convert.FromBase64String(body.GetProperty("signature").GetString()!)))
            return Fail("The lease offer is not signed by the pinned broker identity. Nothing was sealed.");

        var sealedDeks = new Dictionary<string, byte[]>();
        using (var hello = HelloKeyWrapper.Open(create: false))
        {
            foreach (var secret in secrets)
            {
                var dek = SecretEnvelope.UnwrapDek(secret, hello);
                if (dek is null)
                {
                    Console.Error.WriteLine($"  {secret.Slug}: this Hello credential can't open it, skipped.");
                    continue;
                }
                try
                {
                    sealedDeks[secret.Slug] = SealedBox.Seal(offer.LeaseKey, dek, LeaseOffer.DekContext(offer.LeaseId, secret.Slug));
                }
                finally
                {
                    Array.Clear(dek);
                }
            }
        }

        var seal = await client.PostAsync("/lease/seal", new { offer.LeaseId, deks = sealedDeks });
        if (!seal.Ok || seal.Body is not { } result)
            return Fail($"DEKs not accepted: {seal.Describe()}");

        KeyringStore.Lease = new(offer.LeaseId, offer.HardCapAt);
        Console.WriteLine($"Lease {offer.LeaseId} open until {offer.HardCapAt.ToLocalTime():HH:mm}.");
        Console.WriteLine($"  leased:   {Join(result.GetProperty("accepted"))}");
        if (result.GetProperty("rejected").GetArrayLength() > 0)
            Console.WriteLine($"  rejected: {Join(result.GetProperty("rejected"))}");
        Console.WriteLine("Run 'tir agent' to keep it alive and end it when you lock the workstation.");
        return 0;
    }

    public static async Task<int> LockAsync()
    {
        using var client = Client(KeyringStore.RequireBroker(), KeyringStore.Settings);
        var end = await client.PostAsync("/lease/end");
        KeyringStore.Lease = null;
        if (!end.Ok)
            return Fail($"Broker refused: {end.Describe()}");
        Console.WriteLine("Lease ended.");
        return 0;
    }

    public static async Task<int> StatusAsync()
    {
        var broker = KeyringStore.Broker;
        var settings = KeyringStore.Settings;
        Console.WriteLine($"Broker:   {(broker is null ? "not enrolled" : $"{broker.Url} (identity {broker.IdentityKey})")}");
        Console.WriteLine($"Device:   {settings.DeviceId}");
        Console.WriteLine($"Vault:    {settings.VaultPath}" + (File.Exists(settings.VaultPath) ? $" ({VaultFile.Load(settings.VaultPath).Secrets.Count} secrets)" : " (missing)"));
        Console.WriteLine($"Recovery: {(settings.RecoveryPublicKey is null ? "NOT SET (run tir recovery init)" : "set")}");

        if (KeyringStore.Lease is not { } lease || broker is null)
        {
            Console.WriteLine("Lease:    none");
            return 0;
        }
        using var client = Client(broker, settings);
        var heartbeat = await client.PostAsync("/lease/heartbeat", new { lease.LeaseId });
        if (heartbeat.Ok)
            Console.WriteLine($"Lease:    {lease.LeaseId}, open until {lease.HardCapAt.ToLocalTime():HH:mm}");
        else
        {
            Console.WriteLine($"Lease:    {lease.LeaseId} ended ({heartbeat.Describe()})");
            KeyringStore.Lease = null;
        }
        return 0;
    }

    public static async Task<int> GrantAsync(CommandLine args)
    {
        var settings = KeyringStore.Settings;
        var serviceSlug = args.Require(1, "service");
        var service = VaultFile.Load(settings.VaultPath).FindService(serviceSlug)
            ?? throw new UsageException($"No service '{serviceSlug}' in {settings.VaultPath}.");
        var request = new AccessRequest(
            args.Require("--consumer"),
            ObservedProcess: null,
            serviceSlug,
            args.Option("--ceiling"),
            args.Require("--purpose"),
            Terminal.ParseDuration(args.Require("--for")));

        var problems = Consent.Validate(request, service);
        if (problems.Count > 0)
            return Fail(string.Join(Environment.NewLine, problems));

        foreach (var line in Consent.Describe(request, service))
            Console.WriteLine(line);
        if (!Terminal.Confirm("Approve?"))
            return Fail("Not approved.");
        HelloKeyWrapper.ConfirmPresence($"grant\n{serviceSlug}\n{request.Consumer}");

        using var client = Client(KeyringStore.RequireBroker(), settings);
        var minted = await client.PostAsync("/placeholder", request);
        if (!minted.Ok || minted.Body is not { } body)
            return Fail($"Not minted: {minted.Describe()}");
        Console.WriteLine($"Expires {body.GetProperty("expiresAt").GetDateTimeOffset().ToLocalTime():HH:mm}. Placeholder:");
        Console.WriteLine(body.GetProperty("token").GetString());
        return 0;
    }

    public static async Task<int> ElevateAsync(CommandLine args)
    {
        var service = args.Require(1, "service");
        var grant = args.Require(2, "grant");
        var duration = Terminal.ParseDuration(args.Option("--for") ?? "15m");

        Console.WriteLine($"Elevating {service}/{grant} for {duration.TotalMinutes:0} min; confirm with Windows Hello.");
        HelloKeyWrapper.ConfirmPresence($"elevate\n{service}\n{grant}");

        using var client = Client(KeyringStore.RequireBroker(), KeyringStore.Settings);
        var elevated = await client.PostAsync("/elevate", new { service, grant, minutes = (int)Math.Ceiling(duration.TotalMinutes) });
        if (!elevated.Ok || elevated.Body is not { } body)
            return Fail($"Not elevated: {elevated.Describe()}");
        Console.WriteLine($"Elevated until {body.GetProperty("expiresAt").GetDateTimeOffset().ToLocalTime():HH:mm}.");
        return 0;
    }

    public static BrokerClient Client(BrokerPin broker, KeyringSettings settings) =>
        new(broker, settings.DeviceId, KeyringStore.LoadOrCreateDeviceKey());

    static string Join(JsonElement array) => string.Join(", ", array.EnumerateArray().Select(e => e.GetString()));

    static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }
}
