using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;

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
        _ => throw new UsageException("tir env takes list, protect, put-back, set, remove, hook or shell."),
    };

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
            Console.WriteLine($"  {variable.Name}");
        foreach (var set in sealedNow.Folders.OrderBy(f => f.Folder, StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine($"For commands in {set.Folder} ({set.Variables.Count}):");
            foreach (var variable in set.Variables)
                Console.WriteLine($"  {variable.Name}");
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
            var (sealedNow, version) = EnvironmentStore.Open(hello);
            SealedVariable[] added = [new(name, Encoding.UTF8.GetString(bytes))];
            EnvironmentStore.Save(folder is null ? sealedNow.WithGlobal(added) : sealedNow.WithFolder(folder, added), version, hello);
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
        var variables = await FromAppAsync(program, args.Rest, directory) ?? FromTerminal(directory);
        if (ReferenceEquals(variables, Denied))
        {
            Console.Error.WriteLine("Not approved.");
            return 1;
        }

        var start = new ProcessStartInfo(args.Rest[0]) { UseShellExecute = false };
        foreach (var arg in args.Rest.Skip(1))
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
            throw new InvalidOperationException($"Could not start {program}. For a .cmd script or a shell command, run it through the shell: tir run -- cmd /c {string.Join(' ', args.Rest)}");
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

    static IReadOnlyDictionary<string, string> FromTerminal(string directory)
    {
        Console.WriteLine("Windows Hello will ask you to confirm it's you.");
        using var hello = HelloKeyWrapper.Open(create: false);
        var variables = EnvironmentStore.Open(hello).Environment.Resolve(directory);
        if (variables.Count > 0)
            Console.WriteLine($"With {string.Join(", ", variables.Select(v => v.Name))}.");
        return variables.ToDictionary(v => v.Name, v => v.Value, StringComparer.OrdinalIgnoreCase);
    }
}
