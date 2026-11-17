using System.Text.RegularExpressions;
using Tiresias.Access;
using Tiresias.Agent;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary>The <c>tir</c> commands. Each returns the process exit code.</summary>
static class Commands
{
    static readonly Regex Slug = new("^[a-z0-9][a-z0-9-]{0,62}$", RegexOptions.CultureInvariant);

    public static int Enroll(CommandLine args)
    {
        var url = new Uri(args.Require("--broker"));
        var brokerKey = args.Require("--broker-key");
        KeyringStore.ValidateBrokerKey(brokerKey);

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

        var devicePublicKey = KeyringStore.DevicePublicKey();
        Console.WriteLine($"Pinned broker {url} for tenant {tenant} (identity {brokerKey}, vault {vaultPath}).");
        Console.WriteLine("Add this device to the broker's configuration:");
        Console.WriteLine($"  \"Broker\": {{ \"Devices\": {{ \"{settings.DeviceId}\": \"{devicePublicKey}\" }} }}");
        return 0;
    }

    public static int RecoveryInit()
    {
        var raw = RecoveryKey.Create();
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
        Console.WriteLine("Stored the public half only. Clear this terminal's scrollback.");
        return 0;
    }

    public static int VaultAdd(CommandLine args)
    {
        var slug = args.Require(2, "slug");
        if (!Slug.IsMatch(slug))
            throw new UsageException("A slug is lower-case letters, digits and dashes.");
        var settings = KeyringStore.Settings;
        var recovery = RecoveryKey.Wrapper()
            ?? throw new UsageException("No recovery key yet. Run tir recovery init first, so no secret depends on the TPM alone.");

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

    public static async Task<int> UnlockAsync(CommandLine args)
    {
        KeyringStore.RequireBroker();
        var slugs = args.Option("--secrets")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        UnlockResult result;
        using (var hello = HelloKeyWrapper.Open(create: false))
            result = await LeaseControl.UnlockAsync(hello, slugs);
        foreach (var note in result.Notes)
            Console.Error.WriteLine($"  {note}");
        if (!result.Ok)
            return Fail(result.Message);
        Console.WriteLine(result.Message);
        Console.WriteLine($"  leased:   {string.Join(", ", result.Accepted)}");
        if (result.Rejected.Count > 0)
            Console.WriteLine($"  rejected: {string.Join(", ", result.Rejected)}");
        Console.WriteLine("Run 'tir agent' to keep it alive and end it when you lock the workstation.");
        return 0;
    }

    public static async Task<int> LockAsync()
    {
        if (await LeaseControl.LockAsync() is { } refused)
            return Fail($"Broker refused: {refused}");
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

        var remembered = KeyringStore.Lease;
        var (lease, ended) = await LeaseControl.CheckAsync();
        Console.WriteLine(lease is not null ? $"Lease:    {lease.LeaseId}, open until {lease.HardCapAt.ToLocalTime():HH:mm}"
            : remembered is not null ? $"Lease:    {remembered.LeaseId} ended ({ended})"
            : "Lease:    none");
        return 0;
    }

    public static async Task<int> DoctorAsync(CommandLine args)
    {
        var checks = await Tiresias.Client.Doctor.RunAsync(new MachineProbe(args.Option("--projects")));
        foreach (var check in checks)
            Console.WriteLine($"{check.Status switch { Tiresias.Client.DoctorStatus.Ok => "ok  ", Tiresias.Client.DoctorStatus.Warn => "WARN", _ => "FAIL" }}  {check.Name}: {check.Detail}");
        return checks.Any(c => c.Status == Tiresias.Client.DoctorStatus.Fail) ? 1 : 0;
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

        using var client = BrokerClient.For(KeyringStore.RequireBroker());
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

        using var client = BrokerClient.For(KeyringStore.RequireBroker());
        var elevated = await client.PostAsync("/elevate", new { service, grant, minutes = (int)Math.Ceiling(duration.TotalMinutes) });
        if (!elevated.Ok || elevated.Body is not { } body)
            return Fail($"Not elevated: {elevated.Describe()}");
        Console.WriteLine($"Elevated until {body.GetProperty("expiresAt").GetDateTimeOffset().ToLocalTime():HH:mm}.");
        return 0;
    }

    static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }
}
