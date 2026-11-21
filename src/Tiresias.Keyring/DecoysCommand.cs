using Tiresias.Agent;
using Tiresias.Decoys;

namespace Tiresias.Keyring;

/// <summary><c>tir decoys</c>: place, list and remove decoy credentials. No decoy value is printed: the files hold them.</summary>
static class DecoysCommand
{
    public static int Run(CommandLine args) => args.At(1) switch
    {
        "place" => Place(args.Require(2, "kind"), args.At(3)),
        "list" => List(),
        "remove" => Remove(),
        _ => throw new UsageException("tir decoys takes place, list or remove."),
    };

    static int Place(string kind, string? where)
    {
        var placed = DecoyStore.Place(kind switch
        {
            "passwords" => DecoyKind.PasswordsFile,
            "project" => DecoyKind.Project,
            "variables" => DecoyKind.Variables,
            _ => throw new UsageException("A decoy is passwords, project or variables."),
        }, where);
        Console.WriteLine($"Placed a decoy: {placed.Where}.");
        Console.WriteLine("A program that uses it is seen while the app or tir agent runs.");
        return 0;
    }

    static int List()
    {
        if (DecoyStore.Current is not { Placed.Count: > 0 } set)
        {
            Console.WriteLine("No decoys placed. tir decoys place passwords puts one in Documents.");
            return 0;
        }
        foreach (var placed in set.Placed)
            Console.WriteLine($"{placed.Kind,-14} {placed.Where}  (since {placed.Placed:yyyy-MM-dd})");
        Console.WriteLine($"Endpoints: HTTP on 127.0.0.1:{set.HttpPort}, SQL Server on 127.0.0.1:{set.SqlPort}.");
        return 0;
    }

    static int Remove()
    {
        var left = DecoyStore.RemoveAll();
        if (left.Count == 0)
        {
            Console.WriteLine("Every decoy is removed.");
            return 0;
        }
        Console.Error.WriteLine($"Couldn't remove: {string.Join(", ", left)}. Close what holds them and run this again.");
        return 1;
    }
}
