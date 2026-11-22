#if DEBUG
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Text;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.EnvironmentVariables;
using Tiresias.Vault;

namespace Tiresias.App;

/// <summary>
/// Demo mode, Debug builds only: <c>Tiresias.exe --demo [scenario]</c> runs the app on the made-up
/// machine of <c>Demo\&lt;scenario&gt;.json</c> (<see cref="DemoMode"/>, <see cref="DemoScenario"/>),
/// beside the real app and without touching it, with every window capturable.
/// </summary>
static class Demo
{
    public const string DefaultScenario = "everyday";

    /// <summary>The scenario the arguments ask for, or <c>null</c> when they don't ask for demo mode.</summary>
    public static string? Requested(string[] args)
    {
        var at = Array.IndexOf(args, "--demo");
        return at < 0 ? null : at + 1 < args.Length && !args[at + 1].StartsWith('-', StringComparison.Ordinal) ? args[at + 1] : DefaultScenario;
    }

    /// <summary>The scenario running, while demo mode is on.</summary>
    public static string? Scenario { get; private set; }

    /// <summary>What the running scenario shows.</summary>
    public static string? Description { get; private set; }

    /// <summary>Empties the made-up machine and fills it from the scenario, before anything reads a store.</summary>
    /// <returns>Whether the scenario starts unlocked.</returns>
    /// <exception cref="FileNotFoundException">No such scenario.</exception>
    public static bool Start(string name)
    {
        var scenario = DemoScenario.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Demo", name + ".json")));
        DemoMode.Start(helloExists: scenario.SetUp);
        Seed(scenario, DemoMode.Profile!);
        Scenario = name;
        Description = scenario.Description;
        AppLog.Info($"demo mode: scenario {name} in {DemoMode.Profile}");
        return scenario.Unlocked;
    }

    public static void End()
    {
        Scenario = null;
        Description = null;
        DemoMode.End();
    }

    static void Seed(DemoScenario scenario, string profile)
    {
        var now = DateTimeOffset.Now;
        foreach (var (relative, content) in scenario.Files)
        {
            var path = DemoScenario.Target(profile, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, DemoScenario.Expand(content, path, profile, now));
        }
        foreach (var (path, values) in scenario.Registry)
        {
            using var key = UserMachine.CurrentUser.CreateSubKey(path, writable: true);
            foreach (var (name, value) in values)
                if (value is string text)
                    key.SetValue(name, DemoScenario.Expand(text, "", profile, now));
                else
                    key.SetValue(name, (int)value, RegistryValueKind.DWord);
        }
        if (scenario.ProgramRuns.Count > 0)
        {
            using var runs = UserMachine.CurrentUser.CreateSubKey(DemoScenario.UserAssistKey, writable: true);
            foreach (var (path, at) in scenario.ProgramRuns)
                runs.SetValue(DemoScenario.UserAssistName(DemoScenario.Expand(path, "", profile, now)),
                    DemoScenario.UserAssistValue(DateTimeOffset.Parse(DemoScenario.Expand(at, "", profile, now), CultureInfo.InvariantCulture)),
                    RegistryValueKind.Binary);
        }
        foreach (var (name, value) in scenario.Variables)
            UserMachine.SetUserVariable(name, value);
        if (!scenario.SetUp)
            return;

        // The real default names the device after this machine.
        KeyringStore.Settings = KeyringStore.Settings with { DeviceId = "alice-laptop" };
        var pending = RecoveryKey.Create();
        try { pending.Enroll(); }
        finally { CryptographicOperations.ZeroMemory(pending.Paper); }
        // Set up without a broker, as the wizard's solo-less finish leaves it.
        if (KeyringStore.Broker is null)
            (AppSettings.Load() with { SetupSkipped = true }).Save();
        using var hello = HelloKeyWrapper.Open(create: true);
        var recovery = RecoveryKey.Wrapper()!;

        if (scenario.Secrets.Count > 0)
        {
            var vault = VaultEditor.Load();
            SealedSecret[] secrets = [.. scenario.Secrets.Select(s =>
                SecretEnvelope.Seal(s.Key, 1, Encoding.UTF8.GetBytes(s.Value), [hello, recovery], PolicyBinding.Hash(vault, s.Key)))];
            VaultFile.Save(VaultEditor.Path, vault with { Secrets = [.. vault.Secrets, .. secrets] });
        }
        // Parse refused an id that would leave the made-up machine.
        foreach (var (id, document) in scenario.UserSecrets)
        {
            var folder = UserSecretsFiles.Folder(id);
            UserSecretsFiles.Save(folder, UserSecretsFiles.Open(folder, hello), document, hello);
        }
        if (scenario.SealedVariables.Count > 0)
            EnvironmentStore.Save(SealedEnvironment.Empty.WithGlobal(scenario.SealedVariables.Select(v => new SealedVariable(v.Key, v.Value))), 0, hello);
    }
}
#endif
