using Tiresias.Agent;
using Tiresias.Keyring;

const string Usage = """
    tir enroll --broker <url> --broker-key <base64> [--tenant <name>] [--genesis <hex>] [--device <id>] [--vault <path>]

    Every command but enroll and recovery takes --tenant <name> when the Keyring is enrolled with
    several brokers and the service doesn't settle which.

    tir recovery init
    tir vault add <slug> [--from-stdin]
    tir unlock [--secrets a,b]
    tir lock
    tir status
    tir agent
    tir grant <service> --consumer <name> --purpose <text> --for <duration> [--ceiling <grant>]
    tir elevate <service> <grant> [--for 15m]
    tir exec <service>[,<service>...] --purpose <text> [--for 1h] [--ceiling <grant>] -- <command> [args...]
    tir doctor [--projects <dir>]
    """;

var line = new CommandLine(args);
try
{
    TenantSelection.Apply(line);
    return (line.At(0), line.At(1)) switch
    {
        ("enroll", _) => Commands.Enroll(line),
        ("recovery", "init") => Commands.RecoveryInit(),
        ("vault", "add") => Commands.VaultAdd(line),
        ("unlock", _) => await Commands.UnlockAsync(line),
        ("lock", _) => await Commands.LockAsync(),
        ("status", _) => await Commands.StatusAsync(),
        ("agent", _) => await AgentCommand.RunAsync(),
        ("grant", _) => await Commands.GrantAsync(line),
        ("elevate", _) => await Commands.ElevateAsync(line),
        ("exec", _) => await Exec.RunAsync(line),
        ("doctor", _) => await Commands.DoctorAsync(line),
        _ => throw new UsageException("Unknown command."),
    };
}
catch (UsageException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(Usage);
    return 2;
}
catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or IOException or FormatException or System.Security.Cryptography.CryptographicException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}
