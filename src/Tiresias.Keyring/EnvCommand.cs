using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Tiresias.Agent;
using Tiresias.Audit;
using Tiresias.Client;
using Tiresias.EnvironmentVariables;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir env</c> and <c>tir run</c>: user environment variables moved into the sealed environment,
/// handed to one command at a time, or to a terminal through the profile hook. Like
/// <c>tir secrets</c>, nothing here prints a value, except the script <c>tir env shell</c> hands the
/// hook, which PowerShell runs rather than shows.
/// </summary>
static class EnvCommand
{
    /// <summary>Long enough for the user to answer the app's dialog; it denies one nobody answers well before this.</summary>
    static readonly TimeSpan ConsentWait = TimeSpan.FromMinutes(10);

    public static int Run(CommandLine args) => args.At(1) switch
    {
        "list" => List(),
        "protect" => Protect(args),
        "put-back" => PutBack(args),
        "set" => Set(args.Require(2, "name"), Folder(args), args.Flag("--from-stdin")),
        "remove" => Remove(args.Require(2, "name"), Folder(args)),
        "hook" => Hook(args.At(2)),
        "nuget" => NuGet(args),
        "placeholder" => Placeholder(args),
        _ => throw new UsageException("tir env takes list, protect, put-back, set, remove, hook, shell, nuget or placeholder."),
    };

    /// <summary>
    /// <c>tir env placeholder add|list|remove</c>: variables handed out as a broker placeholder,
    /// with the forwarder's URL in the tool's base-URL variable, instead of their value. The real
    /// key is the vault service's secret, so the process never holds it.
    /// </summary>
    static int Placeholder(CommandLine args)
    {
        using var hello = HelloKeyWrapper.Open(create: false);
        var (sealedNow, version) = EnvironmentStore.Open(hello);
        switch (args.At(2))
        {
            case "list":
                if (sealedNow.Placeholders.Count == 0)
                    Console.WriteLine("Every sealed variable is handed out as its value. Use a placeholder instead: tir env placeholder add <NAME> <service>.");
                foreach (var placeholder in sealedNow.Placeholders)
                    Console.WriteLine($"  {placeholder.Variable}  a placeholder for {placeholder.Service}, with {placeholder.BaseUrlVariable}");
                return 0;
            case "add":
                var name = args.Require(3, "NAME");
                var slug = args.Require(4, "service");
                if (!sealedNow.IsSealedAnywhere(name))
                    throw new UsageException($"{name} is not a sealed variable. Seal it first: tir env set {name} (or tir env protect {name}).");
                var baseUrl = args.Option("--base-url") ?? SealedEnvironment.BaseUrlVariableFor(name)
                    ?? throw new UsageException("Name the variable the tool reads its API address from: --base-url (for example OPENAI_BASE_URL).");
                if (sealedNow.IsSealedAnywhere(baseUrl))
                    throw new UsageException($"{baseUrl} is itself a sealed variable, so it can't also carry the forwarder's address.");
                CheckService(slug);
                EnvironmentStore.Save(sealedNow.WithPlaceholder(new(name, slug, baseUrl)), version, hello);
                Console.WriteLine($"{name} is now handed out as a placeholder for {slug}, with {baseUrl} set to {ExecPlan.ServiceUrl(slug, PlaceholderMinter.Endpoint)}.");
                Console.WriteLine("Works with tools that send the key as an Authorization: Bearer header and honour that variable. Terminals pick it up at their next folder change.");
                return 0;
            case "remove":
                var removing = args.Require(3, "NAME");
                if (sealedNow.PlaceholderFor(removing) is null)
                {
                    Console.Error.WriteLine($"{removing} is handed out as its value already. See tir env placeholder list.");
                    return 1;
                }
                EnvironmentStore.Save(sealedNow.WithoutPlaceholder(removing), version, hello);
                Console.WriteLine($"{removing} is handed out as its value again. The vault service keeps its secret.");
                return 0;
            default:
                throw new UsageException("tir env placeholder takes add, list or remove.");
        }
    }

    /// <summary>A placeholder only works for a vault service the forwarder can relay as HTTP, with its key as the Authorization header.</summary>
    static void CheckService(string slug)
    {
        var path = KeyringStore.Settings.VaultPath;
        var service = (File.Exists(path) ? VaultFile.Load(path).FindService(slug) : null)
            ?? throw new UsageException($"No service '{slug}' in the vault. Add it, with the key as its secret (\"Bearer <key>\"): tir service add {slug} --upstream https://api.example.com/v1.");
        if (ExecPlan.IsGitHubApp(service) || service.Upstream.Scheme != Uri.UriSchemeHttps)
            throw new UsageException($"{slug} isn't an https API, so a placeholder can't stand in for its key. Use tir exec {slug} instead.");
    }

    /// <summary>
    /// <c>tir env nuget add|list|remove</c>: which package sources the NuGet plugin answers for, and
    /// with which sealed variable. Sealed with the variables, so a mapping can't be changed behind
    /// your back to send a token elsewhere.
    /// </summary>
    static int NuGet(CommandLine args)
    {
        using var hello = HelloKeyWrapper.Open(create: false);
        var (sealedNow, version) = EnvironmentStore.Open(hello);
        switch (args.At(2))
        {
            case "list":
                if (sealedNow.NuGetSources.Count == 0)
                    Console.WriteLine("No NuGet sources use a sealed variable. Add one: tir env nuget add <source-url> <NAME>.");
                foreach (var source in sealedNow.NuGetSources)
                    Console.WriteLine($"  {source.Source}  {source.Variable} (user name {source.Username})");
                return 0;
            case "add":
                var url = args.Require(3, "source-url");
                var name = args.Require(4, "NAME");
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                    throw new UsageException("The source must be an https URL, as in NuGet.Config: https://pkgs.dev.azure.com/example/_packaging/feed/nuget/v3/index.json.");
                if (!sealedNow.Global.Any(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase)))
                    throw new UsageException($"{name} is not a sealed variable. Seal the token first: tir env set {name} (or tir env protect {name}).");
                EnvironmentStore.Save(sealedNow.WithNuGetSource(new(url, name, args.Option("--username") ?? SealedEnvironment.NuGetDefaultUsername)), version, hello);
                Console.WriteLine($"NuGet now asks Tiresias for {url}, and gets {name} once you allow the program asking.");
                Console.WriteLine("Remove the token from NuGet.Config (packageSourceCredentials) so NuGet asks. Needs the .NET 9.0.200 SDK or later.");
                return 0;
            case "remove":
                var removing = args.Require(3, "source-url");
                var left = sealedNow.WithoutNuGetSource(removing);
                if (left.NuGetSources.Count == sealedNow.NuGetSources.Count)
                {
                    Console.Error.WriteLine($"{removing} isn't mapped. See tir env nuget list.");
                    return 1;
                }
                EnvironmentStore.Save(left, version, hello);
                Console.WriteLine($"NuGet no longer gets a sealed variable for {removing}. The variable itself stays sealed.");
                return 0;
            default:
                throw new UsageException("tir env nuget takes add, list or remove.");
        }
    }

    /// <summary><c>--folder</c> alone means the current directory; absent means the global set.</summary>
    static string? Folder(CommandLine args) =>
        !args.Flag("--folder") ? null : Path.GetFullPath(args.Option("--folder") ?? Directory.GetCurrentDirectory());

    static int List()
    {
        var user = EnvironmentStore.UserVariables();
        using var hello = HelloKeyWrapper.Open(create: false);
        var (sealedNow, _) = EnvironmentStore.Open(hello);
        Console.WriteLine($"Sealed ({sealedNow.Global.Count}):");
        foreach (var variable in sealedNow.Global)
            Console.WriteLine($"  {EnvironmentDelivery.Describe(sealedNow, variable.Name)}");
        foreach (var set in sealedNow.Folders.OrderBy(f => f.Folder, StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine($"For commands in {set.Folder} ({set.Variables.Count}):");
            foreach (var variable in set.Variables)
                Console.WriteLine($"  {EnvironmentDelivery.Describe(sealedNow, variable.Name)}");
        }
        var exposed = user.Where(v => v.LooksSecret).ToArray();
        if (exposed.Length > 0)
        {
            Console.WriteLine($"Still in your Windows environment and look like secrets ({exposed.Length}):");
            foreach (var variable in exposed)
                Console.WriteLine($"  {variable.Name} ({variable.Length} characters)");
            Console.WriteLine("Seal them with tir env protect.");
        }
        return 0;
    }

    /// <summary>With no names: the user variables that look like secrets, after a yes.</summary>
    static int Protect(CommandLine args)
    {
        var names = args.Positional.Skip(2).ToArray();
        if (names.Length == 0)
        {
            names = [.. EnvironmentStore.UserVariables().Where(v => v.LooksSecret).Select(v => v.Name)];
            if (names.Length == 0)
            {
                Console.WriteLine("None of your user environment variables look like secrets. Name one to seal it anyway: tir env protect NAME.");
                return 0;
            }
            Console.WriteLine($"These look like secrets: {string.Join(", ", names)}");
            if (!args.Flag("--yes") && !Terminal.Confirm("Seal them and remove them from your Windows environment?"))
                return 1;
        }
        using var hello = HelloKeyWrapper.Open(create: false);
        var moved = EnvironmentStore.Protect(names, hello);
        var missed = names.Except(moved, StringComparer.OrdinalIgnoreCase).ToArray();
        Console.WriteLine(moved.Count == 0 ? "Nothing was sealed." : $"Sealed {string.Join(", ", moved)}. New programs no longer see them; give them to one with tir run -- <command>.");
        if (moved.Count > 0)
            Console.WriteLine("Programs already running keep their copy until they restart.");
        if (missed.Length > 0)
            Console.WriteLine($"Not a user environment variable, so not moved: {string.Join(", ", missed)}");
        return missed.Length > 0 ? 1 : 0;
    }

    static int PutBack(CommandLine args)
    {
        var names = args.Positional.Skip(2).ToArray();
        if (names.Length == 0)
            throw new UsageException("Name the variables to put back: tir env put-back NAME [NAME...].");
        using var hello = HelloKeyWrapper.Open(create: false);
        var back = EnvironmentStore.PutBack(names, hello);
        Console.WriteLine(back.Count == 0 ? "None of those are sealed in the global set (a folder's variables never came from Windows)." : $"Put {string.Join(", ", back)} back in your Windows environment, readable by every program again.");
        return back.Count == names.Length ? 0 : 1;
    }

    static int Set(string name, string? folder, bool fromStdin)
    {
        var bytes = fromStdin ? Terminal.ReadStdin() : Terminal.ReadHidden($"Value for {name}: ");
        try
        {
            if (bytes.Length == 0)
                throw new UsageException("Empty value. To delete one, use tir env remove.");
            using var hello = HelloKeyWrapper.Open(create: false);
            if (EnvironmentStore.Set(new(name, Encoding.UTF8.GetString(bytes)), folder, hello))
                Console.WriteLine($"Removed the old {name} from your Windows environment. Programs already running keep their copy until they restart.");
        }
        finally
        {
            Array.Clear(bytes);
        }
        Console.WriteLine(folder is null ? $"Sealed {name}." : $"Sealed {name} for commands in {folder}.");
        return 0;
    }

    static int Remove(string name, string? folder)
    {
        using var hello = HelloKeyWrapper.Open(create: false);
        var (sealedNow, version) = EnvironmentStore.Open(hello);
        var present = folder is null
            ? sealedNow.Global.Any(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase))
            : sealedNow.Find(folder)?.Variables.Any(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase)) == true;
        if (!present)
        {
            Console.Error.WriteLine(folder is null
                ? $"{name} is not sealed. For a folder's variable, add --folder <path>."
                : $"{name} is not sealed for {folder}.");
            return 1;
        }
        EnvironmentStore.Save(folder is null ? sealedNow.WithoutGlobal([name]) : sealedNow.WithoutFolder(folder, [name]), version, hello);
        Console.WriteLine(folder is null
            ? $"Removed {name}. Its value is gone; tir env put-back keeps it instead."
            : $"Removed {name} from {folder}. Its value is gone.");
        return 0;
    }

    /// <summary>The profile line's script. Only PowerShell has a hook; other shells use <c>tir run</c>.</summary>
    static int Hook(string? shell)
    {
        if (shell is not (null or "pwsh" or "powershell"))
            throw new UsageException($"No hook for {shell}: only PowerShell (pwsh, powershell) has one. In other shells, run a command with tir run -- <command>.");
        Console.WriteLine(ShellScript.PowerShellHook);
        return 0;
    }

    /// <summary>Set once the "app isn't running" hint was shown in a terminal, so it isn't repeated on every <c>cd</c>.</summary>
    const string HintedVariable = "TIRESIAS_ENV_HINTED";

    /// <summary>
    /// <c>tir env shell</c>, run by the hook: a script that brings the terminal's environment up to
    /// date for its directory. Asks the app, which asks the user once per terminal; hints go to the
    /// error stream so the hook doesn't run them. Without the app nothing changes, so a <c>cd</c>
    /// never raises a Windows Hello prompt of its own.
    /// </summary>
    public static async Task<int> ShellAsync(CommandLine args)
    {
        var shell = int.TryParse(args.Require("--shell"), out var id) ? id : throw new UsageException("--shell takes the shell's process id ($PID).");
        var directory = Path.GetFullPath(args.Require("--directory"));
        ControlReply? reply;
        try
        {
            reply = await ControlClient.TryAsync(new(ControlRequest.ShellEnvironment, Directory: directory, Shell: shell, AskAgain: args.Flag("--ask")), ConsentWait);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
            reply = null;
        }
        if (reply is null)
        {
            if (Environment.GetEnvironmentVariable(HintedVariable) is null)
            {
                Console.Error.WriteLine("Tiresias: the app isn't running, so this terminal has no sealed variables. Start it, then run Update-TiresiasEnvironment.");
                Console.WriteLine($"[Environment]::SetEnvironmentVariable('{HintedVariable}', '1', 'Process')");
            }
            return 0;
        }
        if (reply.Message is { } note)
            Console.Error.WriteLine($"Tiresias: {note}");
        if (!reply.Ok || !reply.Approved || reply.Variables is null)
            return reply.Ok ? 0 : 1;
        var variables = reply.Variables.Select(pair => new SealedVariable(pair.Key, pair.Value)).ToArray();
        Console.Write(ShellScript.PowerShell(ShellScript.Names(Environment.GetEnvironmentVariable(ShellScript.NamesVariable)), variables));
        return 0;
    }

    /// <summary>
    /// <c>tir run -- &lt;command&gt;</c>: the sealed variables for the current directory in that one
    /// process's environment. With the app running it asks there (and unlocks if needed); without
    /// it, the Windows Hello prompt is the consent.
    /// </summary>
    public static async Task<int> RunCommandAsync(CommandLine args)
    {
        if (args.Rest.Count == 0)
            throw new UsageException("Nothing to run. Put the command after --: tir run -- dotnet run.");
        var program = Path.GetFileName(args.Rest[0]);
        var directory = Directory.GetCurrentDirectory();
        var variables = await FromAppAsync(program, args.Rest, directory) ?? await FromTerminalAsync(program, directory);
        if (ReferenceEquals(variables, Denied))
        {
            Console.Error.WriteLine("Not approved.");
            return 1;
        }
        try
        {
            return await StartAsync(program, args.Rest, variables);
        }
        finally
        {
            // Nothing the command leaked outlives it.
            await PlaceholderMinter.RevokeAsync(EnvironmentDelivery.Placeholders(variables.Values));
        }
    }

    static async Task<int> StartAsync(string program, IReadOnlyList<string> commandLine, IReadOnlyDictionary<string, string> variables)
    {
        var start = new ProcessStartInfo(commandLine[0]) { UseShellExecute = false };
        foreach (var arg in commandLine.Skip(1))
            start.ArgumentList.Add(arg);
        foreach (var (name, value) in variables)
            start.Environment[name] = value;
        try
        {
            using var child = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {program}.");
            await child.WaitForExitAsync();
            return child.ExitCode;
        }
        catch (Win32Exception)
        {
            throw new InvalidOperationException($"Could not start {program}. For a .cmd script or a shell command, run it through the shell: tir run -- cmd /c {string.Join(' ', commandLine)}");
        }
    }

    /// <returns>The variables, <see cref="Denied"/> for a denial, or <c>null</c> when the app isn't running.</returns>
    static async Task<IReadOnlyDictionary<string, string>?> FromAppAsync(string program, IReadOnlyList<string> commandLine, string directory)
    {
        ControlReply? reply;
        try
        {
            if (await AppLink.StateAsync() is null)
                return null;
            Console.WriteLine("Waiting for your answer in the Tiresias app...");
            reply = await ControlClient.TryAsync(new(ControlRequest.Environment, commandLine, program, Directory: directory), ConsentWait);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
            return null;
        }
        if (reply is null)
            return null;
        if (!reply.Ok)
            throw new InvalidOperationException(reply.Message ?? "The Tiresias app couldn't hand over the environment.");
        if (reply.Message is { } note)
            Console.WriteLine(note);
        return reply.Approved ? reply.Variables ?? new Dictionary<string, string>() : Denied;
    }

    static readonly IReadOnlyDictionary<string, string> Denied = new Dictionary<string, string>();

    static async Task<IReadOnlyDictionary<string, string>> FromTerminalAsync(string program, string directory)
    {
        Console.WriteLine("Windows Hello will ask you to confirm it's you.");
        SealedEnvironment sealedNow;
        using (var hello = HelloKeyWrapper.Open(create: false))
            sealedNow = EnvironmentStore.Open(hello).Environment;
        var variables = sealedNow.Resolve(directory);
        if (variables.Count > 0)
            Console.WriteLine($"With {string.Join(", ", variables.Select(v => EnvironmentDelivery.Describe(sealedNow, v.Name)))}.");
        // The app isn't running, so tir records the hand-over itself.
        using (var activity = new AuditLog(AgentHost.ActivityPath, TimeProvider.System))
            activity.Append(AgentHost.EnvironmentRecord(true, program, variables.Select(v => EnvironmentDelivery.Describe(sealedNow, v.Name)), "tir run (Windows Hello)"));
        var delivery = await EnvironmentDelivery.DeliverAsync(sealedNow, variables, PlaceholderMinter.Endpoint,
            (placeholder, _) => PlaceholderMinter.MintAsync(placeholder, $"run:{program}", null), CancellationToken.None);
        foreach (var problem in delivery.Problems)
            Console.Error.WriteLine(problem);
        return delivery.Variables;
    }
}
