using Tiresias.Agent;
using Tiresias.Keyring;

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
        ("trust", "bind-hello") => await Commands.TrustBindHelloAsync(),
        ("vault", "add") => Commands.VaultAdd(line),
        ("vault", "migrate") => await ServiceCommand.MigrateAsync(),
        ("service", _) => ServiceCommand.Run(line),
        ("unlock", _) => await Commands.UnlockAsync(line),
        ("lock", _) => await Commands.LockAsync(),
        ("status", _) => await Commands.StatusAsync(),
        ("agent", _) => await AgentCommand.RunAsync(),
        ("grant", _) => await Commands.GrantAsync(line),
        ("elevate", _) => await Commands.ElevateAsync(line),
        ("exec", _) => await Exec.RunAsync(line),
        ("doctor", _) => await Commands.DoctorAsync(line),
        ("advise", _) => Commands.Advise(line),
        ("ai", _) => Commands.Ai(line),
        ("secrets", _) => SecretsCommand.Run(line),
        ("env", "shell") => await EnvCommand.ShellAsync(line),
        ("env", _) => EnvCommand.Run(line),
        ("run", _) => await EnvCommand.RunCommandAsync(line),
        ("decoys", _) => DecoysCommand.Run(line),
        _ => throw new UsageException("Unknown command."),
    };
}
catch (UsageException ex)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(CliUsage.Text);
    return 2;
}
catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or IOException or FormatException or System.Security.Cryptography.CryptographicException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}
