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

        var settings = ProfileAccess.Run(() => KeyringStore.Settings);
        settings = settings with { DeviceId = args.Option("--device") ?? settings.DeviceId };
        var vaultPath = args.Option("--vault") is { } vault ? Path.GetFullPath(vault)
            : ProfileAccess.Run(() => KeyringStore.Tenants.FirstOrDefault(t => t.Name == tenant)?.VaultPath)
            ?? (tenant == KeyringStore.DefaultTenant ? settings.VaultPath : Path.Combine(KeyringStore.Directory, $"vault-{tenant}.json"));
        var enrollment = new TenantConfig(tenant, url, brokerKey, vaultPath, genesis);
        BrokerService.EnrollRemote(enrollment);
        var devicePublicKey = ProfileAccess.Run(() =>
        {
            KeyringStore.Settings = settings;
            KeyringStore.Enroll(enrollment);
            return KeyringStore.DevicePublicKey();
        });
        Console.WriteLine($"Pinned broker {url} for tenant {tenant} (identity {brokerKey}, vault {vaultPath}).");
        Console.WriteLine("Add this device to the broker's configuration:");
        Console.WriteLine($"  \"Broker\": {{ \"Devices\": {{ \"{settings.DeviceId}\": \"{devicePublicKey}\" }} }}");
        return 0;
    }

    public static int RecoveryInit() => ShowNewPaper(RecoveryKey.Create());

    public static int RecoveryRotate()
    {
        Console.WriteLine("The new paper key will cover future writes. Keep the old paper for existing secrets and any trust chain it signed.");
        var paper = ReadPaper("Current paper key: ");
        try
        {
            return ShowNewPaper(RecoveryKey.Rotate(paper));
        }
        finally
        {
            Array.Clear(paper);
        }
    }

    static int ShowNewPaper(PendingRecoveryKey pending)
    {
        try
        {
            BackUpAndEnroll(pending);
        }
        finally
        {
            Array.Clear(pending.Paper);
        }
        Console.WriteLine("Stored the public half only. Clear this terminal's scrollback.");
        return 0;
    }

    static void BackUpAndEnroll(PendingRecoveryKey pending)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected)
            throw new InvalidOperationException("Open an interactive terminal to write down and confirm your new paper key.");
        Console.WriteLine("Write this recovery key on paper. The administrator approval follows the paper check.");
        Console.WriteLine();
        Console.WriteLine(PaperKey.Format(pending.Paper));
        Console.WriteLine();
        ConfirmWrittenDown(PaperKey.Words(pending.Paper));
        ShowRecipient(pending.Paper);
        pending.Enroll();
    }

    static void ShowRecipient(byte[] paper)
    {
        Console.WriteLine("If Windows asks to enroll this paper key, compare this public fingerprint with the administrator prompt:");
        Console.WriteLine(PaperKey.RecipientFingerprint(paper));
    }

    static byte[] ReadPaper(string prompt)
    {
        const string invalid = "The recovery key must contain 13 groups of four letters and digits 2-7.";
        PaperKeyReading? reading;
        if (Console.IsInputRedirected)
            reading = Agent.RecoveryRestore.Read(Console.ReadLine() ?? "");
        else
        {
            var input = Terminal.ReadHidden(prompt);
            try
            {
                reading = Agent.RecoveryRestore.Read(System.Text.Encoding.UTF8.GetString(input));
            }
            finally
            {
                Array.Clear(input);
            }
        }
        if (reading is null)
            throw new UsageException(invalid);
        if (reading.Corrections.Count > 0)
            Console.WriteLine($"Read lookalike letters the other way ({string.Join(", ", reading.Corrections)}). Correct them on your paper.");
        return reading.Key;
    }

    /// <summary>
    /// Restores sealed secrets with the paper recovery key: every one this PC's Windows Hello key can't
    /// open gets a copy for it. Creates the Hello credential when this PC has none yet (one prompt).
    /// </summary>
    public static int RecoveryRestore()
    {
        var raw = ReadPaper("Type your paper recovery key (13 groups of four): ");
        RestoreSummary summary;
        try
        {
            ShowRecipient(raw);
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
            if (!RecoveryKey.IsEnrolled)
            {
                var pending = RecoveryKey.Create();
                raw = pending.Paper;
                BackUpAndEnroll(pending);
            }
            else
            {
                raw = ReadPaper("Type the existing paper recovery key to sign the trust chain: ");
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

    /// <summary>Installs, removes or (for the service manager) runs the solo broker as a Windows service (docs/broker-service.md).</summary>
    public static async Task<int> SoloServiceAsync(CommandLine line)
    {
        switch (line.At(2))
        {
            case "install":
                await BrokerService.InstallAsync();
                Console.WriteLine("The broker now runs as the Tiresias service. Start the Tiresias app again and unlock.");
                return 0;
            case "uninstall":
                BrokerService.Uninstall();
                Console.WriteLine("The Tiresias service is removed. The broker runs inside the app again from its next start.");
                return 0;
            case "run":
                await BrokerService.RunAsync();
                return 0;
            default:
                throw new UsageException("tir solo service install | uninstall");
        }
    }

    /// <summary>Binds this device's Hello key into the trust chain with the paper key (docs/trust-links.md).</summary>
    public static async Task<int> TrustBindHelloAsync()
    {
        Console.WriteLine("Type the recovery key to sign the trust chain (spaces and case don't matter). Windows Hello asks next.");
        var raw = PaperKey.Parse(Console.ReadLine() ?? "")
            ?? throw new InvalidOperationException("That is not a recovery key: it should be 13 groups of four letters and digits 2-7.");
        try
        {
            await TrustLinks.BindHelloAsync(raw);
        }
        finally
        {
            Array.Clear(raw);
        }
        Console.WriteLine("This PC's Windows Hello key is in the trust chain. Adding a device or changing trust now asks for it.");
        return 0;
    }

    static void ConfirmWrittenDown(IReadOnlyList<string> words)
    {
        while (true)
        {
            var (first, second) = PaperKey.Challenge(words.Count);
            Console.Write($"To check it is written down, type group {first + 1}: ");
            var a = Console.ReadLine() ?? throw new InvalidOperationException("Recovery key confirmation ended before enrollment.");
            Console.Write($"and group {second + 1}: ");
            var b = Console.ReadLine() ?? throw new InvalidOperationException("Recovery key confirmation ended before enrollment.");
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
        var recoveryStatus = RecoveryKey.IsEnrolled ? "set"
            : RecoveryKey.NeedsVerification ? "needs enrollment (run tir recovery restore with your paper key)"
            : "NOT SET (run tir recovery init)";
        Console.WriteLine($"Recovery: {recoveryStatus}");
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
        var projects = args.Option("--projects");
        if (projects is not null && !Directory.Exists(projects))
            throw new UsageException($"No folder {projects}.");
        var probe = new MachineProbe(projects);
        // Typing --reach is the consent to look inside (docs/containers-and-vms.md, "Consent").
        var contents = args.Flag("--reach") ? await probe.ReachContentsAsync(Tiresias.Client.ReachScope.All, CancellationToken.None) : null;
        var checks = await Tiresias.Client.Doctor.RunAsync(probe, contents);
        var dismissals = DismissalStore.Load();
        foreach (var check in checks)
        {
            var moves = check is { Now: { } now } ? $" [{now}{(check.Better is { } better ? $" -> {better}" : "")}]" : "";
            Console.WriteLine($"{check.Status switch { Tiresias.Client.DoctorStatus.Ok => "ok  ", Tiresias.Client.DoctorStatus.Warn => "WARN", _ => "FAIL" }}  {check.Name}: {check.Detail}{moves}");
            if (check.Fix is { } fix)
                Console.WriteLine($"      fix: {fix.Instruction}");
            if (check.IsFinding && dismissals.For(check) is { } dismissal)
                Console.WriteLine($"      dismissed {dismissal.At.ToLocalTime():d}: {dismissal.Reason}");
        }
        if (args.Flag("--surface"))
        {
            Console.WriteLine();
            foreach (var line in Tiresias.Client.Doctor.InventoryLines(probe.Inventory(args.Flag("--refresh")), DateTimeOffset.Now))
                Console.WriteLine(line);
        }
        return checks.Any(c => c.Status == Tiresias.Client.DoctorStatus.Fail) ? 1 : 0;
    }

    /// <summary>
    /// <c>tir ai</c>: the agent guide; <c>--snippet</c> the block for CLAUDE.md / AGENTS.md;
    /// <c>--install [&lt;file&gt;]</c> writes that block into the file (Claude Code's user-wide one by default), replacing an earlier copy.
    /// </summary>
    public static int Ai(CommandLine args)
    {
        if (args.Flag("--install"))
        {
            var path = ExpandHome(args.Option("--install") ?? "~/.claude/CLAUDE.md");
            var existing = File.Exists(path) ? File.ReadAllText(path) : null;
            var updated = AiGuide.Install(existing);
            if (updated == existing)
            {
                Console.WriteLine($"{path} already has the Tiresias section.");
                return 0;
            }
            if (Path.GetDirectoryName(Path.GetFullPath(path)) is { } folder)
                Directory.CreateDirectory(folder);
            File.WriteAllText(path, updated);
            Console.WriteLine($"{(existing?.Contains(AiGuide.Begin, StringComparison.Ordinal) == true ? "Updated" : "Added")} the Tiresias section in {path}.");
            return 0;
        }
        Console.WriteLine(args.Flag("--snippet") ? AiGuide.Block : AiGuide.Instructions);
        return 0;
    }

    /// <summary>A leading <c>~</c> as the user's profile folder: PowerShell doesn't expand it for a native command.</summary>
    static string ExpandHome(string path) =>
        path == "~" || path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith(@"~\", StringComparison.Ordinal)
            ? Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[1..].TrimStart('/', '\\'))
            : path;

    /// <summary><c>tir advise "&lt;words&gt;"</c>: the needs the words match, each with its options strongest first, as the app's <i>What do you need?</i> lists them.</summary>
    public static int Advise(CommandLine args)
    {
        var facts = new Tiresias.Client.NeedFacts(HasBroker: KeyringStore.Broker is not null);
        var first = true;
        foreach (var match in Tiresias.Client.NeedMatcher.Match(string.Join(' ', args.Positional.Skip(1))))
        {
            if (!first)
                Console.WriteLine();
            first = false;
            Console.WriteLine(match.Need.Title);
            foreach (var (option, recommended, unavailable) in Tiresias.Client.NeedCatalog.Rank(match.Need, facts))
            {
                var mark = recommended ? "*" : unavailable is not null ? "-" : " ";
                var named = option.Id == match.Preselect ? "  (the service you named)" : "";
                Console.WriteLine($"  {mark} {option.Position}  {option.Title}{(recommended ? "  (recommended)" : "")}{named}");
                Console.WriteLine($"           {option.Summary}");
                if (option.GivesUp is { } givesUp)
                    Console.WriteLine($"           gives up: {givesUp}");
                if (unavailable is not null)
                    Console.WriteLine($"           not here: {unavailable}");
                Console.WriteLine($"           do: {option.Action.Instruction}");
            }
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

        var lines = Consent.Describe(request, service).ToArray();
        foreach (var line in lines)
            Console.WriteLine(line);
        if (!await AppLink.ApproveAsync($"tir grant {serviceSlug}", lines))
            return Fail("Not approved.");
        using var client = BrokerClient.For(await ReachableBrokerAsync());
        SignedApproval approval;
        using (var hello = HelloKeyWrapper.Open(create: false))
            approval = Approvals.Mint(hello, request);
        var minted = await client.PostAsync("/placeholder", approval);
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
        using var client = BrokerClient.For(await ReachableBrokerAsync());
        SignedApproval approval;
        using (var hello = HelloKeyWrapper.Open(create: false))
            approval = Approvals.Sign(hello, (lease, now) => Approval.ForElevate(lease, service, grant, duration, "tir elevate", now));
        var elevated = await client.PostAsync("/elevate", approval);
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
