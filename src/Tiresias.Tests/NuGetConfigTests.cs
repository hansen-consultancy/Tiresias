using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

/// <summary>Finding a NuGet.Config's credentials, planning their move into the sealed environment, and taking them out of the file.</summary>
public class NuGetConfigTests
{
    static readonly string Config = """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <packageSources>
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
            <add key="github" value="https://nuget.pkg.github.com/example/index.json" />
            <add key="my feed" value="https://pkgs.example.com/feed/index.json" />
            <add key="old" value="https://old.example.com/index.json" />
          </packageSources>
          <packageSourceCredentials>
            <github>
              <add key="Username" value="%GH_USER%" />
              <add key="ClearTextPassword" value="%GH_TOKEN%" />
            </github>
            <my_x0020_feed>
              <add key="Username" value="alice" />
              <add key="ClearTextPassword" value="plain-token" />
            </my_x0020_feed>
            <old>
              <add key="Username" value="alice" />
              <add key="Password" value="AQAAANCMnd8BFdERjHoAwE" />
            </old>
            <elsewhere>
              <add key="ClearTextPassword" value="%OTHER%" />
            </elsewhere>
          </packageSourceCredentials>
        </configuration>

        """.ReplaceLineEndings("\n");

    [Test]
    public void Read_finds_each_source_with_how_it_holds_its_password()
    {
        var found = NuGetConfig.Read(Config);

        Assert.That(found.Select(c => (c.Key, c.Source, c.Kind, c.Password)), Is.EqualTo(new[]
        {
            ("github", (string?)"https://nuget.pkg.github.com/example/index.json", NuGetPasswordKind.Variable, (string?)"GH_TOKEN"),
            ("my feed", "https://pkgs.example.com/feed/index.json", NuGetPasswordKind.ClearText, "plain-token"),
            ("old", "https://old.example.com/index.json", NuGetPasswordKind.Encrypted, null),
            ("elsewhere", null, NuGetPasswordKind.Variable, "OTHER"),
        }));
        Assert.That(found[0].UsernameVariable, Is.EqualTo("GH_USER"));
    }

    [TestCase("<configuration />")]
    [TestCase("<packages />")]
    [TestCase("not xml")]
    public void Read_finds_nothing_in_a_file_without_credentials(string xml) =>
        Assert.That(NuGetConfig.Read(xml), Is.Empty);

    [TestCase("%GH_TOKEN%", "GH_TOKEN")]
    [TestCase("%A%B%", null)]
    [TestCase("x%GH_TOKEN%", null)]
    [TestCase("%%", null)]
    [TestCase(null, null)]
    public void Only_a_whole_value_names_a_variable(string? value, string? variable) =>
        Assert.That(NuGetConfig.VariableIn(value), Is.EqualTo(variable));

    [Test]
    public void Taking_credentials_out_leaves_the_rest_of_the_file_as_written()
    {
        var left = NuGetConfig.WithoutCredentials(Config, ["github", "my feed"]);

        Assert.That(left, Does.StartWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>"));
        Assert.That(left, Does.Not.Contain("GH_TOKEN").And.Not.Contain("plain-token").And.Not.Contain("my_x0020_feed"));
        Assert.That(left, Does.Contain("    <old>\n").And.EndWith("</configuration>\n"));
        Assert.That(NuGetConfig.Read(left).Select(c => c.Key), Is.EqualTo(new[] { "old", "elsewhere" }));
    }

    [Test]
    public void Taking_the_last_credentials_out_drops_the_empty_section()
    {
        var left = NuGetConfig.WithoutCredentials(Config, ["github", "my feed", "old", "elsewhere"]);

        Assert.That(left, Does.Not.Contain("packageSourceCredentials"));
        Assert.That(left, Does.Contain("</packageSources>\n</configuration>"));
    }

    [Test]
    public void The_plan_maps_seals_or_says_why_not()
    {
        var sealedNow = SealedEnvironment.Empty.WithFolder(@"C:\src\shop", [new("OTHER", "x")]);
        var found = NuGetConfig.Read(Config).Select(c => ("NuGet.Config", c));

        var steps = NuGetImport.Plan(found, sealedNow, name => name == "GH_TOKEN", name => name == "GH_USER" ? "alice" : null);

        Assert.That(steps[0], Is.EqualTo(new NuGetImportStep("NuGet.Config", steps[0].Credential, "GH_TOKEN", "alice", ProtectFirst: true)));
        Assert.That(steps[1], Is.EqualTo(new NuGetImportStep("NuGet.Config", steps[1].Credential, "NUGET_MY_FEED_TOKEN", "alice", SealClearText: true)));
        Assert.That(steps[2].Skip, Does.Contain("encrypted"));
        Assert.That(steps[3].Skip, Does.Contain("another config file"));
    }

    [Test]
    public void A_sealed_variable_is_mapped_without_sealing_again_and_a_folder_one_is_refused()
    {
        var credential = new NuGetConfigCredential("github", "https://nuget.pkg.github.com/example/index.json", null, NuGetPasswordKind.Variable, "GH_TOKEN");
        string? None(string _) => null;

        var global = NuGetImport.Plan([("f", credential)], SealedEnvironment.Empty.WithGlobal([new("GH_TOKEN", "t")]), _ => false, None);
        var folder = NuGetImport.Plan([("f", credential)], SealedEnvironment.Empty.WithFolder(@"C:\src", [new("GH_TOKEN", "t")]), _ => false, None);
        var nowhere = NuGetImport.Plan([("f", credential)], SealedEnvironment.Empty, _ => false, None);

        Assert.That(global[0], Is.EqualTo(new NuGetImportStep("f", credential, "GH_TOKEN", SealedEnvironment.NuGetDefaultUsername)));
        Assert.That(folder[0].Skip, Does.Contain("folder only"));
        Assert.That(nowhere[0].Skip, Does.Contain("isn't set"));
    }

    [Test]
    public void A_plain_text_token_is_not_sealed_over_a_name_in_use()
    {
        var credential = new NuGetConfigCredential("my feed", "https://pkgs.example.com/feed/index.json", "alice", NuGetPasswordKind.ClearText, "plain-token");

        var steps = NuGetImport.Plan([("f", credential)], SealedEnvironment.Empty.WithGlobal([new("NUGET_MY_FEED_TOKEN", "x")]), _ => false, _ => null);

        Assert.That(steps[0].Skip, Does.Contain("is taken"));
    }

    [Test]
    public void Files_are_the_nearest_first_then_the_users_own()
    {
        var root = Directory.CreateTempSubdirectory("tiresias-nuget-").FullName;
        try
        {
            var repo = Directory.CreateDirectory(Path.Combine(root, "repo", "src")).FullName;
            var appData = Directory.CreateDirectory(Path.Combine(root, "appdata", "NuGet", "config")).Parent!.Parent!.FullName;
            File.WriteAllText(Path.Combine(root, "repo", "nuget.config"), "<configuration />");
            File.WriteAllText(Path.Combine(appData, "NuGet", "NuGet.Config"), "<configuration />");
            File.WriteAllText(Path.Combine(appData, "NuGet", "config", "extra.config"), "<configuration />");

            Assert.That(NuGetConfig.Files(repo, appData).Select(f => Path.GetRelativePath(root, f)), Is.EqualTo(new[]
            {
                Path.Combine("repo", "nuget.config"),
                Path.Combine("appdata", "NuGet", "NuGet.Config"),
                Path.Combine("appdata", "NuGet", "config", "extra.config"),
            }));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
