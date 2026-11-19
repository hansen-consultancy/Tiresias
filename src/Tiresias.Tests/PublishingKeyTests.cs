using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

public class PublishingKeyTests
{
    const string Secret = "s3cr3t-value-never-shown";

    static DoctorCheck[] Checks(string path, string text, bool inProfile = true, params string[] userVariables) =>
        [.. Doctor.PublishingKeys([new DoctorToolFile(path, text, inProfile)], userVariables)];

    static void AssertNoValue(IEnumerable<DoctorCheck> checks)
    {
        foreach (var check in checks)
        {
            Assert.That(check.Name + check.Detail + check.Fix?.Instruction, Does.Not.Contain(Secret));
            Assert.That(check.IsFinding);
        }
    }

    const string NuGetFeed = $"""
        <configuration>
          <packageSources>
            <add key="feed" value="https://pkgs.example.com/feed/index.json" />
          </packageSources>
          <packageSourceCredentials>
            <feed>
              <add key="Username" value="alice" />
              <add key="ClearTextPassword" value="{Secret}" />
            </feed>
          </packageSourceCredentials>
        </configuration>
        """;

    [Test]
    public void A_NuGet_feed_token_in_plain_text_is_moved_to_Tiresias()
    {
        var check = Checks(@"C:\Users\alice\AppData\Roaming\NuGet\NuGet.Config", NuGetFeed).Single();

        Assert.That(check.Fix, Is.EqualTo(new ImportNuGetCredentials(@"C:\Users\alice\AppData\Roaming\NuGet\NuGet.Config", true)));
        Assert.That((check.Now, check.Better), Is.EqualTo((Position.Plaintext, Position.SealedApproved)));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.OpenEnvironment));
        AssertNoValue([check]);
    }

    [Test]
    public void A_project_NuGet_config_copies_the_import_command_for_its_folder()
    {
        var check = Checks(@"C:\src\app\nuget.config", NuGetFeed, inProfile: false).Single();

        Assert.That(check.Fix!.Instruction, Is.EqualTo(@"tir env nuget import, run in C:\src\app"));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.CopyCommand));
    }

    [Test]
    public void A_NuGet_feed_naming_a_variable_is_a_finding_only_while_the_variable_is_in_Windows()
    {
        var config = NuGetFeed.Replace(Secret, "%FEED_TOKEN%", StringComparison.Ordinal);

        Assert.That(Checks("NuGet.Config", config, true, "FEED_TOKEN").Single().Detail, Does.Contain("%FEED_TOKEN%"));
        Assert.That(Checks("NuGet.Config", config), Is.Empty);
    }

    [Test]
    public void A_NuGet_push_key_is_a_finding_without_a_fix()
    {
        const string config = $"""
            <configuration>
              <apikeys>
                <add key="https://api.nuget.org/v3/index.json" value="{Secret}" />
              </apikeys>
            </configuration>
            """;

        var check = Checks("NuGet.Config", config).Single();

        Assert.That(check.Name, Is.EqualTo("NuGet push key for https://api.nuget.org/v3/index.json in NuGet.Config"));
        Assert.That(check.Fix, Is.Null);
        Assert.That(check.Now, Is.EqualTo(Position.Plaintext));
        Assert.That(check.Detail, Does.Contain("trusted publishing"));
        AssertNoValue([check]);
    }

    [TestCase("<configuration><packageSources>")]
    [TestCase("not xml at all")]
    [TestCase("")]
    public void A_malformed_NuGet_config_is_no_finding(string text) =>
        Assert.That(Checks("NuGet.Config", text), Is.Empty);

    [Test]
    public void An_npm_token_in_plain_text_is_sealed_as_a_reference()
    {
        var npmrc = $"registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={Secret}\n//npm.pkg.github.com/:_authToken=\"{Secret}\"\n";

        var checks = Checks(@"C:\Users\alice\.npmrc", npmrc);

        Assert.That(checks.Select(c => c.Fix), Is.EqualTo(new DoctorFix[]
        {
            new SealRegistryToken(@"C:\Users\alice\.npmrc", "//registry.npmjs.org/:_authToken", "NPM_TOKEN"),
            new SealRegistryToken(@"C:\Users\alice\.npmrc", "//npm.pkg.github.com/:_authToken", "NPM_NPM_PKG_GITHUB_COM_TOKEN"),
        }));
        Assert.That(checks[0].Detail, Does.Contain("trusted publishing"));
        Assert.That(checks[1].Detail, Does.Not.Contain("trusted publishing"));
        Assert.That(FindingView.Button(checks[0].Fix)?.Action, Is.EqualTo(FixAction.SealToken));
        AssertNoValue(checks);
    }

    [TestCase("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")]
    [TestCase("//registry.npmjs.org/:_authToken=\n")]
    [TestCase("; //registry.npmjs.org/:_authToken=abc\n")]
    [TestCase("[not ini\n=\n")]
    public void An_npm_reference_comment_or_empty_entry_is_no_finding(string npmrc) =>
        Assert.That(Checks(".npmrc", npmrc), Is.Empty);

    [Test]
    public void A_bare_npm_password_is_for_the_registry_the_file_names()
    {
        var check = Checks(".npmrc", $"registry=https://npm.example.com/\r\n_password={Secret}\r\n").Single();

        Assert.That(check.Name, Is.EqualTo("npm token for npm.example.com in .npmrc"));
        Assert.That(((SealRegistryToken)check.Fix!).Variable, Is.EqualTo("NPM_NPM_EXAMPLE_COM_PASSWORD"));
    }

    [Test]
    public void An_npmrc_rewrite_replaces_only_the_value_and_keeps_line_endings()
    {
        var npmrc = $"registry=https://registry.npmjs.org/\r\n//registry.npmjs.org/:_authToken = {Secret}\r\nsave-exact=true";

        Assert.That(NpmRc.ValueOf(npmrc, "//registry.npmjs.org/:_authToken"), Is.EqualTo(Secret));
        Assert.That(NpmRc.WithReference(npmrc, "//registry.npmjs.org/:_authToken", "NPM_TOKEN"),
            Is.EqualTo("registry=https://registry.npmjs.org/\r\n//registry.npmjs.org/:_authToken = ${NPM_TOKEN}\r\nsave-exact=true"));
    }

    const string PyPiRcText = $"""
        [distutils]
        index-servers = pypi testpypi

        [pypi]
        username = __token__
        password = {Secret}

        [testpypi]
        repository = https://test.pypi.org/legacy/
        password: {Secret}

        """;

    [Test]
    public void A_PyPI_password_is_sealed_as_TWINE_PASSWORD_for_pypi_only()
    {
        var checks = Checks(@"C:\Users\alice\.pypirc", PyPiRcText);

        Assert.That(checks.Select(c => c.Name), Is.EqualTo(new[] { @"PyPI password for pypi in C:\Users\alice\.pypirc", @"PyPI password for testpypi in C:\Users\alice\.pypirc" }));
        Assert.That(checks[0].Fix, Is.EqualTo(new SealRegistryToken(@"C:\Users\alice\.pypirc", "pypi", "TWINE_PASSWORD")));
        Assert.That(checks[1].Fix, Is.Null);
        Assert.That(checks[1].Now, Is.EqualTo(Position.Plaintext));
        AssertNoValue(checks);
    }

    [Test]
    public void A_pypirc_rewrite_removes_only_that_sections_password()
    {
        Assert.That(PyPiRc.PasswordOf(PyPiRcText, "PyPI"), Is.EqualTo(Secret));

        var without = PyPiRc.WithoutPassword(PyPiRcText, "pypi");

        Assert.That(PyPiRc.Read(without), Is.EqualTo(new[] { new PyPiCredential("testpypi") }));
        Assert.That(without, Does.Contain("username = __token__"));
    }

    [Test]
    public void Other_files_and_unreadable_ones_are_no_finding() =>
        Assert.That(Doctor.PublishingKeys([new("appsettings.json", NuGetFeed, false), new(".npmrc", null, true)], []), Is.Empty);
}
