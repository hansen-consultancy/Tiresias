using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir env</c> and <c>tir run</c>: user environment variables moved into the sealed environment,
/// and handed to one command at a time. Like <c>tir secrets</c>, nothing here prints a value.
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
        "set" => Set(args.Require(2, "name"), args.Flag("--from-stdin")),
        "remove" => Remove(args.Require(2, "name")),
        _ => throw new UsageException("tir env takes list, protect, put-back, set or remove."),
    };

    static int List()
    {
        var user = EnvironmentStore.UserVariables();
        using var hello = HelloKeyWrapper.Open(create: false);
        var (sealedNow, _) = EnvironmentStore.Open(hello);
        Console.WriteLine($"Sealed ({sealedNow.Count}):");
        foreach (var variable in sealedNow)
            Console.WriteLine($"  {variable.Name}");
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
        Console.WriteLine(back.Count == 0 ? "None of those are sealed." : $"Put {string.Join(", ", back)} back in your Windows environment, readable by every program again.");
        return back.Count == names.Length ? 0 : 1;
    }

    static int Set(string name, bool fromStdin)
    {
        var bytes = fromStdin ? Terminal.ReadStdin() : Terminal.ReadHidden($"Value for {name}: ");
        try
        {
            if (bytes.Length == 0)
                throw new UsageException("Empty value. To delete one, use tir env remove.");
            using var hello = HelloKeyWrapper.Open(create: false);
            var (sealedNow, version) = EnvironmentStore.Open(hello);
            EnvironmentStore.Save(SealedVariables.With(sealedNow, [new(name, Encoding.UTF8.GetString(bytes))]), version, hello);
        }
        finally
        {
            Array.Clear(bytes);
        }
        Console.WriteLine($"Sealed {name}.");
        return 0;
    }

    static int Remove(string name)
    {
        using var hello = HelloKeyWrapper.Open(create: false);
        var (sealedNow, version) = EnvironmentStore.Open(hello);
        var left = SealedVariables.Without(sealedNow, [name]);
        if (left.Count == sealedNow.Count)
        {
            Console.Error.WriteLine($"{name} is not sealed.");
            return 1;
        }
        EnvironmentStore.Save(left, version, hello);
        Console.WriteLine($"Removed {name}. Its value is gone; tir env put-back keeps it instead.");
        return 0;
    }

    /// <summary>
    /// <c>tir run -- &lt;command&gt;</c>: the sealed variables in that one process's environment. With the
    /// app running it asks there (and unlocks if needed); without it, the Windows Hello prompt is the consent.
    /// </summary>
    public static async Task<int> RunCommandAsync(CommandLine args)
    {
        if (args.Rest.Count == 0)
            throw new UsageException("Nothing to run. Put the command after --: tir run -- dotnet run.");
        var program = Path.GetFileName(args.Rest[0]);
        var variables = await FromAppAsync(program, args.Rest) ?? FromTerminal();
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

    /// <returns>The variables, an empty set for a denial, or <c>null</c> when the app isn't running.</returns>
    static async Task<IReadOnlyDictionary<string, string>?> FromAppAsync(string program, IReadOnlyList<string> commandLine)
    {
        ControlReply? reply;
        try
        {
            if (await AppLink.StateAsync() is null)
                return null;
            Console.WriteLine("Waiting for your answer in the Tiresias app...");
            reply = await ControlClient.TryAsync(new(ControlRequest.Environment, commandLine, program), ConsentWait);
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

    static IReadOnlyDictionary<string, string> FromTerminal()
    {
        Console.WriteLine("Windows Hello will ask you to confirm it's you.");
        using var hello = HelloKeyWrapper.Open(create: false);
        var (variables, _) = EnvironmentStore.Open(hello);
        if (variables.Count > 0)
            Console.WriteLine($"With {string.Join(", ", variables.Select(v => v.Name))}.");
        return variables.ToDictionary(v => v.Name, v => v.Value, StringComparer.OrdinalIgnoreCase);
    }
}
