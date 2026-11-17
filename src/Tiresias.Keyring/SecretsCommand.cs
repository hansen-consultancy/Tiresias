using System.Text;
using Tiresias.Agent;
using Tiresias.UserSecrets;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir secrets</c>: a project's protected user secrets by key. Values go in (typed without echo,
/// or piped), never out: there is no command that prints a value or writes the file back in clear.
/// Each command costs one Windows Hello prompt.
/// </summary>
static class SecretsCommand
{
    public static int Run(CommandLine args)
    {
        var folder = UserSecretsFiles.Folder(args.Option("--id") ?? UserSecretsFiles.IdFromProject(args.Option("--project") ?? Environment.CurrentDirectory));
        return args.At(1) switch
        {
            "list" => List(folder),
            "set" => Set(folder, args.Require(2, "key"), args.Flag("--from-stdin")),
            "remove" => Remove(folder, args.Require(2, "key")),
            _ => throw new UsageException("tir secrets takes list, set or remove."),
        };
    }

    static int List(UserSecretsFolder folder)
    {
        using var hello = HelloKeyWrapper.Open(create: false);
        var load = UserSecretsFiles.Open(folder, hello);
        Console.WriteLine($"{folder.Id}: {load.Keys.Count} key(s), {(load.Version == 0 ? "not sealed yet" : $"sealed v{load.Version}")}");
        foreach (var key in load.Keys)
            Console.WriteLine($"  {key}");
        if (load.PlaintextKeys.Count > 0)
            Console.WriteLine($"{load.PlaintextKeys.Count} key(s) are on disk in clear; the next tir secrets set or app start seals them.");
        return 0;
    }

    static int Set(UserSecretsFolder folder, string key, bool fromStdin)
    {
        var bytes = fromStdin ? Terminal.ReadStdin() : Terminal.ReadHidden($"Value for {key}: ");
        try
        {
            if (bytes.Length == 0)
                throw new UsageException("Empty value. To delete a key, use tir secrets remove.");
            using var hello = HelloKeyWrapper.Open(create: false);
            var load = UserSecretsFiles.Open(folder, hello);
            UserSecretsEdit.Set(load.Document, key, Encoding.UTF8.GetString(bytes));
            UserSecretsFiles.Save(folder, load, load.Document, hello);
        }
        finally
        {
            Array.Clear(bytes);
        }
        Console.WriteLine($"Set {key} in {folder.Id} (sealed).");
        return 0;
    }

    static int Remove(UserSecretsFolder folder, string key)
    {
        using var hello = HelloKeyWrapper.Open(create: false);
        var load = UserSecretsFiles.Open(folder, hello);
        if (!UserSecretsEdit.Remove(load.Document, key))
        {
            Console.Error.WriteLine($"{folder.Id} has no key '{key}'. tir secrets list shows the keys.");
            return 1;
        }
        UserSecretsFiles.Save(folder, load, load.Document, hello);
        Console.WriteLine($"Removed {key} from {folder.Id} (sealed).");
        return 0;
    }
}
