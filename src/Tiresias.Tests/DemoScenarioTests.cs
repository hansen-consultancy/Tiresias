using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class DemoScenarioTests
{
    const string Profile = @"C:\Users\Public\Tiresias-demo\alice";

    static readonly DateTimeOffset Now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void Every_section_may_be_left_out()
    {
        var scenario = DemoScenario.Parse("{}");

        Assert.That(scenario.SetUp, Is.True);
        Assert.That(scenario.Unlocked, Is.False);
        Assert.That(scenario.Files, Is.Empty);
        Assert.That(scenario.Secrets, Is.Empty);
        Assert.That(scenario.UserSecrets, Is.Empty);
        Assert.That(scenario.Variables, Is.Empty);
        Assert.That(scenario.SealedVariables, Is.Empty);
    }

    [Test]
    public void A_scenario_reads_its_sections()
    {
        var scenario = DemoScenario.Parse("""
            {
              // comments are allowed
              "description": "A laptop",
              "setUp": false,
              "unlocked": true,
              "files": { "source/shop/Shop.csproj": "<Project />" },
              "secrets": { "llm-key": "sk-demo" },
              "userSecrets": { "shop-api": { "ConnectionStrings": { "Db": "Server=db.example.com" } } },
              "variables": { "OPENAI_API_KEY": "sk-demo" },
              "sealedVariables": { "GITHUB_TOKEN": "ghp_demo" },
            }
            """);

        Assert.That(scenario.Description, Is.EqualTo("A laptop"));
        Assert.That(scenario.SetUp, Is.False);
        Assert.That(scenario.Unlocked, Is.True);
        Assert.That(scenario.Files["source/shop/Shop.csproj"], Is.EqualTo("<Project />"));
        Assert.That(scenario.Secrets["llm-key"], Is.EqualTo("sk-demo"));
        Assert.That(scenario.UserSecrets["shop-api"]["ConnectionStrings"]!["Db"]!.GetValue<string>(), Is.EqualTo("Server=db.example.com"));
        Assert.That(scenario.Variables["OPENAI_API_KEY"], Is.EqualTo("sk-demo"));
        Assert.That(scenario.SealedVariables["GITHUB_TOKEN"], Is.EqualTo("ghp_demo"));
    }

    [TestCase("source/shop/Shop.csproj")]
    [TestCase(@"AppData\Local\Tiresias\projects.json")]
    [TestCase(".gitconfig")]
    public void A_path_inside_the_profile_is_written_there(string relative) =>
        Assert.That(DemoScenario.Target(Profile, relative), Does.StartWith(Profile + Path.DirectorySeparatorChar));

    [TestCase("")]
    [TestCase("../outside.txt")]
    [TestCase(@"source\..\..\outside.txt")]
    [TestCase("./here.txt")]
    [TestCase("source//x")]
    [TestCase(@"C:\Windows\x.txt")]
    [TestCase("C:x.txt")]
    [TestCase("/etc/x")]
    [TestCase(@"\\server\share\x")]
    public void A_path_leaving_the_profile_is_refused(string relative) =>
        Assert.That(() => DemoScenario.Target(Profile, relative), Throws.ArgumentException);

    [TestCase("..")]
    [TestCase(@"..\..\outside")]
    [TestCase("a/b")]
    [TestCase("C:x")]
    [TestCase("")]
    public void A_user_secrets_id_that_is_not_one_folder_is_refused(string id) =>
        Assert.That(() => DemoScenario.Parse($$"""{ "userSecrets": { "{{id.Replace(@"\", @"\\", StringComparison.Ordinal)}}": {} } }"""),
            Throws.InstanceOf<System.Text.Json.JsonException>());

    [Test]
    public void A_user_secrets_id_names_one_folder() =>
        Assert.That(DemoScenario.Parse("""{ "userSecrets": { "5f0c2a6e-0b1d.v2_x": {} } }""").UserSecrets, Has.Count.EqualTo(1));

    [TestCase(Profile + @"\source\ShopApi\secrets.json", true)]
    [TestCase(Profile, false)]
    [TestCase(Profile + @"\..\bob\x.pfx", false)]
    [TestCase(Profile + @"-other\x.pfx", false)]
    [TestCase(@"C:\Users\someone\source\x.pfx", false)]
    [Platform("Win")]
    public void Only_a_path_inside_the_profile_is_the_demos_to_delete(string path, bool inside) =>
        Assert.That(DemoScenario.Inside(Profile, path), Is.EqualTo(inside));

    static IEnumerable<string> Scenarios()
    {
        for (var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Tiresias.slnx")))
                return Directory.EnumerateFiles(Path.Combine(dir.FullName, "src", "Tiresias.App", "Demo"), "*.json");
        throw new DirectoryNotFoundException("Tiresias.slnx not found above the test directory.");
    }

    [TestCaseSource(nameof(Scenarios))]
    public void Every_shipped_scenario_parses_and_stays_in_its_profile(string file)
    {
        var scenario = DemoScenario.Parse(File.ReadAllText(file));

        Assert.That(scenario.Description, Is.Not.Empty);
        foreach (var relative in scenario.Files.Keys)
            Assert.That(() => DemoScenario.Target(Profile, relative), Throws.Nothing, relative);
    }

    [Test]
    public void Registry_values_are_text_or_whole_numbers()
    {
        var scenario = DemoScenario.Parse("""{ "registry": { "Software\\App": { "DisplayName": "App", "NoRepair": 1 } } }""");

        Assert.That(scenario.Registry[@"Software\App"]["DisplayName"], Is.EqualTo("App"));
        Assert.That(scenario.Registry[@"Software\App"]["NoRepair"], Is.EqualTo(1));
        Assert.That(() => DemoScenario.Parse("""{ "registry": { "Software\\App": { "Size": 1.5 } } }"""),
            Throws.InstanceOf<System.Text.Json.JsonException>());
    }

    [Test]
    public void A_program_run_reads_back_as_windows_records_it()
    {
        var path = Profile + @"\AppData\Local\Programs\Editor\Editor.exe";
        var lastRun = Now.AddDays(-120);

        var runs = Tiresias.Client.Doctor.UserAssistRuns([(DemoScenario.UserAssistName(path), DemoScenario.UserAssistValue(lastRun))], _ => null);

        Assert.That(runs.Single().Path, Is.EqualTo(path));
        Assert.That(runs.Single().LastRun, Is.EqualTo(lastRun));
    }

    [Test]
    public void The_profile_token_is_escaped_in_json_only()
    {
        Assert.That(DemoScenario.Expand("""{"folders":["{{profile}}\\source"]}""", "projects.json", Profile, Now),
            Is.EqualTo("""{"folders":["C:\\Users\\Public\\Tiresias-demo\\alice\\source"]}"""));
        Assert.That(DemoScenario.Expand("dir={{profile}}", ".npmrc", Profile, Now), Is.EqualTo($"dir={Profile}"));
    }

    [TestCase("{{now}}", "2026-11-21T12:00:00.0000000+00:00")]
    [TestCase("{{now-90m}}", "2026-11-21T10:30:00.0000000+00:00")]
    [TestCase("{{now-2h}}", "2026-11-21T10:00:00.0000000+00:00")]
    [TestCase("{{now-3d}}", "2026-11-18T12:00:00.0000000+00:00")]
    [TestCase("{{later}}", "{{later}}")]
    public void Time_tokens_are_before_now(string token, string expected) =>
        Assert.That(DemoScenario.Expand(token, "activity.jsonl", Profile, Now), Is.EqualTo(expected));
}
