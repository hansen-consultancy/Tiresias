using System.Reflection;
using System.Text.RegularExpressions;
using Tiresias.Access;
using Tiresias.Agent;
using Tiresias.Client;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary>The <c>tir</c> commands. Each returns the process exit code.</summary>
static class Commands
{
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
            Console.WriteLine(PaperKey.Format(raw));
            Console.WriteLine();
        }
        finally
        {
            Array.Clear(raw);
        }
        Console.WriteLine("Stored the public half only. Clear this terminal's scrollback.");
        return 0;
    }

    /// <summary>
    /// Restores sealed secrets with the paper recovery key: every one this PC's Windows Hello key can't
    /// open gets a copy for it. Creates the Hello credential when this PC has none yet (one prompt).
    /// </summary>
    public static int RecoveryRestore()
    {
        Console.WriteLine("Type your recovery key (13 groups of four; spaces and case don't matter).");
        var raw = PaperKey.Parse(Console.ReadLine() ?? "")
            ?? throw new UsageException("That is not a recovery key: it should be 13 groups of four letters and digits 2-7.");
        RestoreSummary summary;
        try
        {
            Console.WriteLine("Windows Hello will ask you to confirm it's you.");
            using var hello = HelloKeyWrapper.Open(create: true);
            summary = Agent.RecoveryRestore.Run(raw, hello);
        }
        finally
        {
            Array.Clear(raw);
        }

        Console.WriteLine(summary.Restored == 0
            ? summary.NotOpened.Count == 0
                ? "Nothing needed restoring: Windows Hello on this PC opens every sealed secret."
                : "Nothing restored with this recovery key."
            : $"Restored {summary.Restored} sealed {(summary.Restored == 1 ? "item" : "items")}; Windows Hello on this PC opens {(summary.Restored == 1 ? "it" : "them")} now.");
        if (summary.AlreadyOpen > 0 && summary.Restored > 0)
            Console.WriteLine($"{summary.AlreadyOpen} already opened with this PC's Windows Hello.");
        if (summary.KeyAdopted)
            Console.WriteLine("This PC now uses this recovery key too, so the same paper covers your secrets here.");
        if (summary.OtherKeyKept)
            Console.WriteLine("This PC keeps its own recovery key as well: secrets sealed here since its setup need that paper. Keep both.");
        if (summary.NotOpened.Count > 0)
        {
            Console.WriteLine($"{summary.NotOpened.Count} did not open with this recovery key (sealed with another one, or damaged):");
            foreach (var name in summary.NotOpened)
                Console.WriteLine($"  {name}");
            return 1;
        }
        return 0;
    }

    /// <summary>
    /// Sets up solo mode: the broker runs inside the app (or <c>tir agent</c>) on this device. The
    /// recovery key co-signs the one-device trust chain, so it is created here when there is none,
    /// and asked back when there is.
    /// </summary>
    public static int SoloInit()
    {
        byte[]? raw = null;
        try
        {
            if (KeyringStore.Settings.RecoveryPublicKey is null)
            {
                raw = RecoveryKey.Create();
                Console.WriteLine("Recovery key. Write it on paper now; it is shown once and stored nowhere.");
                Console.WriteLine("It opens your secrets if Windows Hello or this PC is lost, and it signs this device's trust chain.");
                Console.WriteLine();
                Console.WriteLine(PaperKey.Format(raw));
                Console.WriteLine();
                ConfirmWrittenDown(PaperKey.Words(raw));
            }
            else
            {
                Console.WriteLine("This device already has a recovery key. Type it to sign the trust chain (spaces and case don't matter).");
                raw = PaperKey.Parse(Console.ReadLine() ?? "")
                    ?? throw new InvalidOperationException("That is not a recovery key: it should be 13 groups of four letters and digits 2-7.");
            }
            SoloBroker.Setup(raw);
        }
        finally
        {
            if (raw is not null)
                Array.Clear(raw);
        }
        Console.WriteLine("Solo mode is set up. The broker runs inside the Tiresias app; start the app (or tir agent) and unlock.");
        Console.WriteLine("Trade-off: no fixed egress IP, and secrets stay on this machine. tir doctor lists what that means.");
        return 0;
    }

    static void ConfirmWrittenDown(IReadOnlyList<string> words)
    {
        while (true)
        {
            var (first, second) = PaperKey.Challenge(words.Count);
            Console.Write($"To check it is written down, type group {first + 1}: ");
            var a = Console.ReadLine() ?? "";
            Console.Write($"and group {second + 1}: ");
            var b = Console.ReadLine() ?? "";
            if (PaperKey.Confirm(words, (first, second), a, b))
            {
                Console.Clear();
                return;
            }
            Console.WriteLine("Those don't match. Check what you wrote and try again.");
        }
    }

    /// <summary>The pinned broker; in solo mode, first checks something hosts it, so the failure says what to do.</summary>
    public static async Task<BrokerPin> ReachableBrokerAsync()
    {
        var broker = KeyringStore.RequireBroker();
        if (KeyringStore.Tenant is { Solo: true } && !await SoloBroker.ReachableAsync())
            throw new InvalidOperationException("The solo broker runs inside the Tiresias app, which isn't running. Start the app (or tir agent), then try again.");
        return broker;
    }

    public static int VaultAdd(CommandLine args)
    {
        var slug = args.Require(2, "slug");
        if (!ServicePlanner.IsSlug(slug))
            throw new UsageException("A slug is lower-case letters, digits and dashes.");
        var version = SealSecret(slug, args.Flag("--from-stdin"));
        Console.WriteLine($"Sealed {slug} v{version} into {VaultEditor.Path}. {PickedUp()}");
        return 0;
    }

    /// <summary>Reads a secret's value (typed without echo, or piped in with <paramref name="fromStdin"/>) and seals it into the vault.</summary>
    /// <returns>The version written.</returns>
    public static int SealSecret(string slug, bool fromStdin)
    {
        if (RecoveryKey.Wrapper() is null)
            throw new UsageException("No recovery key yet. Run tir recovery init first, so no secret depends on the TPM alone.");
        var value = fromStdin
            ? Terminal.ReadStdin()
            : Terminal.ReadHidden($"Value for {slug} (the whole Authorization header, e.g. 'Bearer sk-...'): ");
        try
        {
            if (value.Length == 0)
                throw new UsageException("Empty value.");
            return VaultEditor.SealSecret(slug, value);
        }
        finally
        {
            Array.Clear(value);
        }
    }

    /// <summary>How a vault change reaches the broker.</summary>
    public static string PickedUp() => KeyringStore.Tenant is { Solo: true }
        ? "The solo broker uses the change from its next request; no need to lock and unlock."
        : "Copy that file to the broker's VaultPath and restart the broker.";

    public static async Task<int> UnlockAsync(CommandLine args)
    {
        if (args.Option("--secrets") is null && await AppLink.SendAsync(ControlRequest.Unlock) is { } reply)
            return reply.Ok ? Done(reply.Message) : Fail($"The Tiresias app couldn't unlock: {reply.Message}");
        await ReachableBrokerAsync();
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
        if (KeyringStore.Tenant is not { Solo: true })
            Console.WriteLine("Run 'tir agent' to keep it alive and end it when you lock the workstation.");
        return 0;
    }

    public static async Task<int> LockAsync()
    {
        if (await AppLink.SendAsync(ControlRequest.Lock) is { } reply)
            return reply.Ok ? Done(reply.Message) : Fail(reply.Message ?? "The Tiresias app couldn't lock.");
        if (await LeaseControl.LockAsync() is { } refused)
            return Fail($"Broker refused: {refused}");
        Console.WriteLine("Lease ended.");
        return 0;
    }

    public static async Task<int> StatusAsync()
    {
        var broker = KeyringStore.Broker;
        var settings = KeyringStore.Settings;
        Console.WriteLine($"Broker:   {(broker is null ? "not enrolled" : $"{broker.Url} (identity {broker.IdentityKey})")}{(KeyringStore.Tenant is { Solo: true } ? " - Solo, hosted by the app" : "")}");
        Console.WriteLine($"Device:   {settings.DeviceId}");
        Console.WriteLine($"Vault:    {settings.VaultPath}" + (File.Exists(settings.VaultPath) ? $" ({VaultFile.Load(settings.VaultPath).Secrets.Count} secrets)" : " (missing)"));
        Console.WriteLine($"Recovery: {(settings.RecoveryPublicKey is null ? "NOT SET (run tir recovery init)" : "set")}");
        var app = await AppLink.PingAsync();
        Console.WriteLine($"App:      {app?.State ?? "not running (start Tiresias, or run tir agent)"}");
        if (app?.Build is { } build)
            Console.WriteLine($"          {build}, from {app.Folder}");
        // Which tir answered: a stale one earlier on PATH shows up here.
        var tirVersion = typeof(Commands).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0];
        Console.WriteLine($"tir:      {tirVersion}, from {Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory)}");

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

        var lines = Consent.Describe(request, service).ToArray();
        foreach (var line in lines)
            Console.WriteLine(line);
        if (!await AppLink.ApproveAsync($"tir grant {serviceSlug}", lines))
            return Fail("Not approved.");
        HelloKeyWrapper.ConfirmPresence($"grant\n{serviceSlug}\n{request.Consumer}");

        using var client = BrokerClient.For(await ReachableBrokerAsync());
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

        using var client = BrokerClient.For(await ReachableBrokerAsync());
        var elevated = await client.PostAsync("/elevate", new { service, grant, minutes = (int)Math.Ceiling(duration.TotalMinutes) });
        if (!elevated.Ok || elevated.Body is not { } body)
            return Fail($"Not elevated: {elevated.Describe()}");
        Console.WriteLine($"Elevated until {body.GetProperty("expiresAt").GetDateTimeOffset().ToLocalTime():HH:mm}.");
        return 0;
    }

    static int Done(string? message)
    {
        if (message is not null)
            Console.WriteLine(message);
        return 0;
    }

    static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }
}
