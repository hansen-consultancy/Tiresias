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
            new(Now.AddHours(-5), [new("dotnet", "acme.cli", "1.1.0"), new("npm", "sass", "1.0.0", "1.2.0")]),
            [new("Chat", StartupEntry.RunKey, @"C:\Chat\chat.exe", true, "Chat"), new("Tray", StartupEntry.RunKey, @"C:\Tray\tray.exe", null, "Tray", InTray: true)],
            [new(@"C:\Programs\VS Code\Code.exe", "github", Now.AddDays(-3)), new(@"C:\Programs\VS Code\Code.exe", "openai", Now.AddDays(-200))],
            []);

        Assert.That(Doctor.InventoryLines(inventory, Now), Is.EqualTo(new[]
        {
            "Extensions",
            "  VS Code (2): reached github in 90 days",
            "    acme.helper 1.0.0, unknown publisher, updated unknown",
            "    beta.tool 2.0.0, Beta, updated 2026-11-09",
            "Global tools (listed 2026-11-19 05:00)",
            "  dotnet: acme.cli 1.1.0",
            "  npm: sass 1.0.0, 1.2.0 available",
            "Starts at log-on",
            @"  Chat (Run key): C:\Chat\chat.exe, signed, last opened unknown",
            @"  Tray (Run key): C:\Tray\tray.exe, signature unchecked, used from the tray",
        }));
    }

    [Test]
    public void No_listing_is_due() => Assert.That(ToolSnapshot.IsDue(null, Now), Is.True);

    [TestCase(-23, false)]
    [TestCase(-24, true)]
    [TestCase(-72, true)]
    [TestCase(2, true)]
    public void A_listing_is_taken_again_after_a_day_or_from_the_future(int hours, bool due) =>
        Assert.That(ToolSnapshot.IsDue(new(Now.AddHours(hours), []), Now), Is.EqualTo(due));

    [Test]
    public void A_listing_round_trips_through_its_file()
    {
        var snapshot = new ToolSnapshot(Now, [new("npm", "@acme/cli", "3.0.0", "3.1.0"), new("pipx", "bare", null)], [new("Acme App", "Acme.App", "1.0", "1.1")]);

        var read = ToolSnapshot.Parse(snapshot.ToJson());

        Assert.That(read?.At, Is.EqualTo(Now));
        Assert.That(read?.Tools, Is.EqualTo(snapshot.Tools));
        Assert.That(read?.WingetPackages, Is.EqualTo(snapshot.WingetPackages));
    }

    [Test]
    public void The_file_holds_names_and_versions_only()
    {
        var json = new ToolSnapshot(Now, [new("dotnet", "acme.cli", "1.1.0")]).ToJson();

        using var document = System.Text.Json.JsonDocument.Parse(json);
        Assert.That(document.RootElement.EnumerateObject().Select(p => p.Name), Is.EqualTo(new[] { "version", "at", "tools", "winget" }));
        Assert.That(document.RootElement.GetProperty("tools")[0].EnumerateObject().Select(p => p.Name), Is.EqualTo(new[] { "manager", "id", "version", "latest" }));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("not json")]
    [TestCase("[]")]
    [TestCase("""{ "version": 1, "at": "2026-11-19T10:00:00+00:00", "tools": [] }""")]
    [TestCase("""{ "version": 2, "at": "yesterday", "tools": [] }""")]
    [TestCase("""{ "version": 2, "at": "2026-11-19T10:00:00+00:00", "tools": {} }""")]
    [TestCase("""{ "version": 2, "at": "2026-11-19T10:00:00+00:00", "tools": [{ "manager": "npm" }] }""")]
    [TestCase("""{ "version": 2, "at": "2026-11-19T10:00:00+00:00", "tools": [], "winget": [{ "name": "Acme" }] }""")]
    public void A_damaged_or_other_version_file_is_listed_again(string? json) =>
        Assert.That(ToolSnapshot.Parse(json), Is.Null);
}
