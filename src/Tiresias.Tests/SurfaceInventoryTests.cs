using NUnit.Framework;
using Tiresias.Client;

namespace Tiresias.Tests;

public class SurfaceInventoryTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);

    [Test]
    public void Dotnet_tools_come_from_its_table()
    {
        const string output = """
            Package Id                    Version          Commands
            --------------------------------------------------------------
            acme.cli                      1.1.0            acme
            other.tool                    2.0.0-beta.1     other

            """;

        Assert.That(Doctor.GlobalTools("dotnet", output), Is.EqualTo(new GlobalTool[] { new("dotnet", "acme.cli", "1.1.0"), new("dotnet", "other.tool", "2.0.0-beta.1") }));
    }

    [Test]
    public void Npm_globals_come_from_its_json()
    {
        const string output = """{ "name": "npm", "dependencies": { "sass": { "version": "1.105.1", "overridden": false }, "@acme/cli": { "version": "3.0.0" } } }""";

        Assert.That(Doctor.GlobalTools("npm", output), Is.EqualTo(new GlobalTool[] { new("npm", "sass", "1.105.1"), new("npm", "@acme/cli", "3.0.0") }));
    }

    [Test]
    public void Pipx_packages_come_from_their_main_package()
    {
        const string output = """{ "venvs": { "acme": { "metadata": { "main_package": { "package_version": "0.9.2" } } }, "bare": {} } }""";

        Assert.That(Doctor.GlobalTools("pipx", output), Is.EqualTo(new GlobalTool[] { new("pipx", "acme", "0.9.2"), new("pipx", "bare", null) }));
    }

    [Test]
    public void Cargo_crates_come_from_their_header_lines()
    {
        const string output = "ripgrep v14.1.0:\n    rg\nacme-cli v0.3.1:\n    acme\n";

        Assert.That(Doctor.GlobalTools("cargo", output), Is.EqualTo(new GlobalTool[] { new("cargo", "ripgrep", "14.1.0"), new("cargo", "acme-cli", "0.3.1") }));
    }

    [TestCase("npm", "not json")]
    [TestCase("npm", "[1]")]
    [TestCase("pipx", "{ \"venvs\": 3 }")]
    [TestCase("dotnet", "")]
    [TestCase("yarn", "{}")]
    public void Output_that_isnt_the_managers_lists_nothing(string manager, string output) =>
        Assert.That(Doctor.GlobalTools(manager, output), Is.Empty);

    [Test]
    public void The_inventory_says_what_each_host_reached_and_what_isnt_known()
    {
        var code = new ExtensionHost("VS Code", "Code.exe", "code");
        var inventory = new SurfaceInventory(
            [new(code, "acme.helper", "1.0.0", null, null), new(code, "beta.tool", "2.0.0", "Beta", Now.AddDays(-10))],
            [new("dotnet", "acme.cli", "1.1.0")],
            [new("Chat", StartupEntry.RunKey, @"C:\Chat\chat.exe", true, "Chat"), new("Tray", StartupEntry.RunKey, @"C:\Tray\tray.exe", null, "Tray", InTray: true)],
            [new(@"C:\Programs\VS Code\Code.exe", "github", Now.AddDays(-3)), new(@"C:\Programs\VS Code\Code.exe", "openai", Now.AddDays(-200))],
            []);

        Assert.That(Doctor.InventoryLines(inventory, Now), Is.EqualTo(new[]
        {
            "Extensions",
            "  VS Code (2): reached github in 90 days",
            "    acme.helper 1.0.0, unknown publisher, updated unknown",
            "    beta.tool 2.0.0, Beta, updated 2026-11-09",
            "Global tools",
            "  dotnet: acme.cli 1.1.0",
            "Starts at log-on",
            @"  Chat (Run key): C:\Chat\chat.exe, signed, last opened unknown",
            @"  Tray (Run key): C:\Tray\tray.exe, signature unchecked, used from the tray",
        }));
    }
}
