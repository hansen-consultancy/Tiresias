using Tiresias.Agent;
using Tiresias.Keyring;

const string Usage = """
    tir enroll --broker <url> --broker-key <base64> [--tenant <name>] [--genesis <hex>] [--device <id>] [--vault <path>]

    Every command but enroll and recovery takes --tenant <name> when the Keyring is enrolled with
    several brokers and the service doesn't settle which.

    tir recovery init
    tir recovery restore
        Gives sealed secrets back to this PC's Windows Hello with the paper recovery key: after
        moving to a new PC, resetting Windows Hello, or copying secrets from another machine.
    tir solo init
        Solo mode: the broker runs inside the Tiresias app on this PC, no server needed. Creates
        the recovery key if there is none (or asks for it) and a one-device trust chain.
    tir vault add <slug> [--from-stdin]
    tir service add <slug> --upstream <https-url> [--secret <slug>] [--method GET]... [--allow <regex>]...
                    [--deny <regex>]... [--grant <name>] [--elevation] [--from-stdin]
        Adds a service with one grant. The secret defaults to the service's slug and is asked for
        (without echo) when the vault doesn't have it yet; methods default to GET; with no --allow,
        every path is allowed. A solo broker uses the change from its next request.
    tir service list
    tir service remove <slug>
        Removes the service, keeps its secret.
    tir unlock [--secrets a,b]
    tir lock
    tir status
    tir agent
        When the Tiresias app runs, it is the agent: unlock and lock go through it, and grant and
        exec ask for approval in its dialog. tir agent is for when the app isn't running.
    tir grant <service> --consumer <name> --purpose <text> --for <duration> [--ceiling <grant>]
    tir elevate <service> <grant> [--for 15m]
    tir exec <service>[,<service>...] --purpose <text> [--for 1h] [--ceiling <grant>] -- <command> [args...]
    tir doctor [--projects <dir>]

    tir secrets list [--project <path> | --id <UserSecretsId>]
    tir secrets set <key> [--from-stdin] [--project <path> | --id <UserSecretsId>]
    tir secrets remove <key> [--project <path> | --id <UserSecretsId>]
        A project's protected user secrets (the project in the current folder by default).
        Values are typed without echo or piped in; no command prints one.
    """;

var line = new CommandLine(args);
try
{
    TenantSelection.Apply(line);
    return (line.At(0), line.At(1)) switch
    {
        ("enroll", _) => Commands.Enroll(line),
        ("recovery", "init") => Commands.RecoveryInit(),
        ("recovery", "restore") => Commands.RecoveryRestore(),
        ("solo", "init") => Commands.SoloInit(),
        ("vault", "add") => Commands.VaultAdd(line),
        ("service", _) => ServiceCommand.Run(line),
        ("unlock", _) => await Commands.UnlockAsync(line),
        ("lock", _) => await Commands.LockAsync(),
        ("status", _) => await Commands.StatusAsync(),
        ("agent", _) => await AgentCommand.RunAsync(),
        ("grant", _) => await Commands.GrantAsync(line),
        ("elevate", _) => await Commands.ElevateAsync(line),
        ("exec", _) => await Exec.RunAsync(line),
        ("doctor", _) => await Commands.DoctorAsync(line),
        ("secrets", _) => SecretsCommand.Run(line),
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
