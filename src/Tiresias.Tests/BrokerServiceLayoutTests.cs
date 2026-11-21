using Tiresias.Client;

namespace Tiresias.Tests;

/// <summary>Where the solo broker's Windows service lives and how it is registered (docs/broker-service.md).</summary>
public class BrokerServiceLayoutTests
{
    [Test]
    public void The_service_runs_the_admin_only_copy_under_its_virtual_account()
    {
        var args = BrokerServiceLayout.CreateArguments(@"C:\Program Files\Tiresias\Broker\tir.exe");
        Assert.That(args, Is.EqualTo(new[]
        {
            "create", "Tiresias", "binPath=", "\"C:\\Program Files\\Tiresias\\Broker\\tir.exe\" solo service run",
            "obj=", @"NT SERVICE\Tiresias", "start=", "auto", "DisplayName=", "Tiresias broker",
        }));
    }

    [Test]
    public void The_state_folder_is_for_system_admins_and_the_service_only()
    {
        var acl = BrokerServiceLayout.StateFolderAcl("state");
        Assert.That(acl, Does.Contain("/inheritance:r"));
        Assert.That(acl.Where(a => a.Contains("(OI)", StringComparison.Ordinal)), Is.EqualTo(new[] { "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", @"NT SERVICE\Tiresias:(OI)(CI)M" }));
        Assert.That(BrokerServiceLayout.VaultFolderAcl("vault"), Is.EqualTo(new[] { "vault", "/grant", @"NT SERVICE\Tiresias:(OI)(CI)R" }));
    }

    [Test]
    public void Every_broker_path_but_the_vault_is_in_the_state_folder_and_marks_persist()
    {
        var state = Path.Combine("data", "Tiresias", "Broker");
        var settings = BrokerServiceLayout.BrokerSettings(state, new(Path.Combine("home", "vault.json"), new string('a', 64), "UTC"));
        Assert.That(settings["Broker:HighWaterPath"], Does.StartWith(state));
        Assert.That(settings.Where(s => s.Key.EndsWith("Path", StringComparison.Ordinal) && s.Key != "Broker:VaultPath").Select(s => s.Value),
            Has.All.StartsWith(state));
        Assert.That(settings["Broker:IdentifyLoopbackCaller"], Is.EqualTo("true"));
    }

    [Test]
    public void The_config_round_trips_and_an_incomplete_one_is_refused()
    {
        var config = new BrokerServiceConfig("vault.json", new string('a', 64), "UTC");
        Assert.That(BrokerServiceConfig.Read(config.Write()), Is.EqualTo(config));
        Assert.That(() => BrokerServiceConfig.Read("""{"vaultPath":"v"}"""u8.ToArray()), Throws.InstanceOf<InvalidDataException>());
    }
}
