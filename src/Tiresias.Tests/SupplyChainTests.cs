using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

public class SupplyChainTests
{
    static readonly string Profile = Path.Combine("C:", "Users", "alice");

    static DoctorToolchain Tool(Toolchain tool, string? version, string? file = null, string fileName = "settings", Dictionary<string, string>? variables = null) =>
        new(tool, version, file is null ? [] : [new DoctorFile(Path.Combine(Profile, fileName), file)], variables ?? []);

    static Dictionary<string, DoctorCheck> Lines(params DoctorToolchain[] tools) =>
        Doctor.SupplyChain(tools).ToDictionary(c => c.Name);

    [Test]
    public void Npm_before_12_runs_every_install_script_and_has_no_age()
    {
        var lines = Lines(Tool(Toolchain.Npm, "11.12.0"));

        Assert.That(lines["npm install scripts"].Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(lines["npm install scripts"].Fix!.Instruction, Does.Contain("ignore-scripts true"));
        Assert.That(lines["npm release age"].Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(lines["npm release age"].Fix, Is.EqualTo(new ChangeToolSetting("npm config set min-release-age 7")));
    }

    [Test]
    public void Npm_12_with_a_release_age_passes_both()
    {
        var lines = Lines(Tool(Toolchain.Npm, "12.2.3", "min-release-age=7\r\nallow-scripts=esbuild\r\n", ".npmrc"));

        Assert.That(lines.Values.Select(c => (c.Status, c.IsFinding)), Is.All.EqualTo((DoctorStatus.Ok, false)));
        Assert.That(lines["npm release age"].Detail, Does.Contain("7 days"));
    }

    [Test]
    public void Npm_before_11_10_is_told_to_update_before_it_can_set_an_age() =>
        Assert.That(Lines(Tool(Toolchain.Npm, "10.9.2"))["npm release age"].Fix!.Instruction, Does.StartWith("npm install -g npm@latest"));

    [Test]
    public void An_environment_variable_wins_over_the_file()
    {
        var lines = Lines(Tool(Toolchain.Npm, "11.12.0", "ignore-scripts=false\n", ".npmrc",
            new() { ["npm_config_ignore_scripts"] = "true", ["NPM_CONFIG_MIN_RELEASE_AGE"] = "3" }));

        Assert.That(lines["npm install scripts"].Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(lines["npm release age"].Detail, Does.Contain("3 days"));
    }

    [Test]
    public void The_users_npmrc_wins_over_npms_global_one()
    {
        var npm = Path.Combine(Profile, "AppData", "Roaming", "npm");
        var files = Doctor.NpmSettingsFiles(Profile, npm);
        var tool = new DoctorToolchain(Toolchain.Npm, "11.12.0",
            [new(files[0], "ignore-scripts=false\nmin-release-age=1\n"), new(files[1], "ignore-scripts=true\nmin-release-age=7\n")], new Dictionary<string, string>());

        Assert.That(files[1], Is.EqualTo(Path.Combine(Profile, ".npmrc")));
        Assert.That(Lines(tool)["npm install scripts"].Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(Lines(tool)["npm release age"].Detail, Does.Contain("7 days"));
    }

    [Test]
    public void Pips_appdata_file_wins_over_the_legacy_one()
    {
        var roaming = Path.Combine(Profile, "AppData", "Roaming");
        var files = Doctor.PipSettingsFiles(Profile, roaming);
        var tool = new DoctorToolchain(Toolchain.Pip, "26.1",
            [new(files[0], "[global]\nonly-binary = :none:\n"), new(files[1], "[global]\nonly-binary = :all:\n")], new Dictionary<string, string>());

        Assert.That(files[1], Is.EqualTo(Path.Combine(roaming, "pip", "pip.ini")));
        Assert.That(Lines(tool)["pip install scripts"].Detail, Does.Contain("wheels only"));
    }

    [Test]
    public void Pnpm_of_unknown_version_may_run_every_install_script()
    {
        var line = Lines(Tool(Toolchain.Pnpm, null))["pnpm install scripts"];

        Assert.That(line.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(line.Detail, Does.Contain("version unknown"));
    }

    [TestCase("false")]
    [TestCase("7 day")]
    [TestCase("none")]
    public void Yarn_with_an_unreadable_age_gate_warns_naming_it(string gate)
    {
        var line = Lines(Tool(Toolchain.Yarn, "4.19.0", $"npmMinimalAgeGate: {gate}\n", ".yarnrc.yml"))["Yarn release age"];

        Assert.That(line.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(line.Detail, Does.Contain(gate));
    }

    [Test]
    public void Pnpm_with_an_unreadable_release_age_warns_naming_it()
    {
        var line = Lines(Tool(Toolchain.Pnpm, "11.3.0", "minimumReleaseAge: false\n", "config.yaml"))["pnpm release age"];

        Assert.That(line.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(line.Detail, Does.Contain("false"));
    }

    [Test]
    public void Pnpm_10_reads_npmrc_and_pnpm_11_only_its_yaml()
    {
        var ten = new DoctorToolchain(Toolchain.Pnpm, "10.20.0", [new(Path.Combine(Profile, ".npmrc"), "minimum-release-age=10080\n")], new Dictionary<string, string>());
        var eleven = ten with { Version = "11.3.0" };
        var elevenOff = eleven with { Settings = [.. eleven.Settings, new(Path.Combine(Profile, "config.yaml"), "minimumReleaseAge: 0\n")] };

        Assert.That(Lines(ten)["pnpm release age"].Detail, Does.Contain("7 days"));
        Assert.That(Lines(eleven)["pnpm release age"].Detail, Does.Contain("a day old, its default"));
        Assert.That(Lines(elevenOff)["pnpm release age"].Status, Is.EqualTo(DoctorStatus.Warn));
    }

    [Test]
    public void Pnpm_allowing_every_build_is_a_warning()
    {
        var lines = Lines(Tool(Toolchain.Pnpm, "12.23.0", "dangerouslyAllowAllBuilds: true\n", "config.yaml"));

        Assert.That(lines["pnpm install scripts"].Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(Lines(Tool(Toolchain.Pnpm, "9.15.0"))["pnpm install scripts"].Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(Lines(Tool(Toolchain.Pnpm, "10.0.0"))["pnpm install scripts"].Status, Is.EqualTo(DoctorStatus.Ok));
    }

    [Test]
    public void Yarn_without_a_known_version_is_judged_by_its_settings()
    {
        var unset = Lines(Tool(Toolchain.Yarn, null));
        var set = Lines(Tool(Toolchain.Yarn, null, "enableScripts: false\nnpmMinimalAgeGate: 7d\n", ".yarnrc.yml"));
        var recent = Lines(Tool(Toolchain.Yarn, "4.19.0"));

        Assert.That(unset.Values.Select(c => c.Status), Is.All.EqualTo(DoctorStatus.Warn));
        Assert.That(set.Values.Select(c => c.Status), Is.All.EqualTo(DoctorStatus.Ok));
        Assert.That(set["Yarn release age"].Detail, Does.Contain("7 days"));
        Assert.That(recent.Values.Select(c => c.Status), Is.All.EqualTo(DoctorStatus.Ok));
    }

    [Test]
    public void Yarn_takes_a_bare_number_as_minutes()
    {
        var lines = Lines(Tool(Toolchain.Yarn, null, "npmMinimalAgeGate: 2880\nenableScripts: true\n", ".yarnrc.yml"));

        Assert.That(lines["Yarn release age"].Detail, Does.Contain("2 days"));
        Assert.That(lines["Yarn install scripts"].Status, Is.EqualTo(DoctorStatus.Warn));
    }

    [Test]
    public void Bun_reads_its_age_in_seconds_under_install()
    {
        var on = Lines(Tool(Toolchain.Bun, "1.4.5", "[install]\nminimumReleaseAge = 604800 # a week\n", ".bunfig.toml"));
        var off = Lines(Tool(Toolchain.Bun, "1.4.5", "minimumReleaseAge = 604800\n", ".bunfig.toml"));

        Assert.That(on["Bun release age"].Detail, Does.Contain("7 days"));
        Assert.That(off["Bun release age"].Status, Is.EqualTo(DoctorStatus.Warn), "outside [install] it isn't the setting");
    }

    [Test]
    public void A_quoted_value_with_a_trailing_comment_is_read()
    {
        Assert.That(Lines(Tool(Toolchain.Bun, "1.4.5", "[install]\nminimumReleaseAge = \"604800\" # a week\n", ".bunfig.toml"))["Bun release age"].Detail, Does.Contain("7 days"));
        Assert.That(Lines(Tool(Toolchain.Yarn, "4.19.0", "npmMinimalAgeGate: \"7d\" # a week\n", ".yarnrc.yml"))["Yarn release age"].Detail, Does.Contain("7 days"));
        Assert.That(Lines(Tool(Toolchain.Pnpm, "11.3.0", "minimumReleaseAge: '10080' # a week\n", "config.yaml"))["pnpm release age"].Detail, Does.Contain("7 days"));
    }

    [Test]
    public void A_quoted_value_keeps_a_hash_inside_it()
    {
        var line = Lines(Tool(Toolchain.Yarn, "4.19.0", "npmMinimalAgeGate: \"7d #x\" # a week\n", ".yarnrc.yml"))["Yarn release age"];

        Assert.That(line.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(line.Detail, Does.Contain("7d #x"));
    }

    const string GatedNuGet = """
        <configuration>
          <packageSources>
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
            <add key="nuget.org" value="https://api.nuget.org/v3/index.json" minPublishAgeHours="168" />
          </packageSources>
          <config>
            <add key="signatureValidationMode" value="require" />
          </config>
        </configuration>
        """;

    [Test]
    public void NuGet_with_every_source_gated_and_signatures_required_passes()
    {
        var lines = Lines(Tool(Toolchain.NuGet, "11.0.100", GatedNuGet, "NuGet.Config"));

        Assert.That(lines.Values.Select(c => (c.Status, c.IsFinding)), Is.All.EqualTo((DoctorStatus.Ok, false)));
        Assert.That(lines["NuGet release age"].Detail, Does.Contain("7 days"));
    }

    [Test]
    public void NuGet_before_the_11_SDK_is_told_to_update_first()
    {
        var lines = Lines(Tool(Toolchain.NuGet, "10.0.203", "<configuration><packageSources><add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" /></packageSources></configuration>", "NuGet.Config"));

        Assert.That(lines["NuGet release age"].Fix!.Instruction, Does.StartWith("install the .NET 11 SDK"));
        Assert.That(lines["NuGet signatures"].Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(lines["NuGet signatures"].IsFinding, "a suggestion, not a warning");
    }

    [Test]
    public void NuGet_names_no_private_source()
    {
        var lines = Lines(Tool(Toolchain.NuGet, "11.0.100",
            "<configuration><packageSources><add key=\"corp\" value=\"https://pkgs.example.com/feed/index.json\" /></packageSources></configuration>", "NuGet.Config"));

        Assert.That(lines["NuGet release age"].Fix!.Instruction, Is.EqualTo("dotnet nuget update source <source> --min-publish-age-hours 168"));
    }

    [Test]
    public void NuGet_partly_gated_names_the_source_still_ungated()
    {
        static string Fix(string sources) => Lines(Tool(Toolchain.NuGet, "11.0.100",
            $"<configuration><packageSources>{sources}</packageSources></configuration>", "NuGet.Config"))["NuGet release age"].Fix!.Instruction;
        const string Org = "<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" minPublishAgeHours=\"168\" />";
        const string Corp = "<add key=\"corp\" value=\"https://pkgs.example.com/feed/index.json\" />";

        Assert.That(Fix(Org + Corp), Does.StartWith("dotnet nuget update source <source> "));
        Assert.That(Fix(Org.Replace(" minPublishAgeHours=\"168\"", "", StringComparison.Ordinal) + Corp.Replace(" />", " minPublishAgeHours=\"168\" />", StringComparison.Ordinal)),
            Does.StartWith("dotnet nuget update source nuget.org "));
    }

    [Test]
    public void Pip_reads_install_and_global_sections()
    {
        var set = Lines(Tool(Toolchain.Pip, "26.1", "[install]\nuploaded-prior-to = P7D\n[global]\nonly-binary = :all:\n", "pip.ini"));
        var old = Lines(Tool(Toolchain.Pip, "25.3"));

        Assert.That(set.Values.Select(c => (c.Status, c.IsFinding)), Is.All.EqualTo((DoctorStatus.Ok, false)));
        Assert.That(old["pip release age"].Fix!.Instruction, Does.StartWith("python -m pip install --upgrade pip"));
        Assert.That(old["pip install scripts"].Status, Is.EqualTo(DoctorStatus.Ok), "wheels only is suggested, not warned about");
    }

    [Test]
    public void Uv_exclude_newer_from_its_toml_or_its_variable()
    {
        Assert.That(Lines(Tool(Toolchain.Uv, "0.11.21", "exclude-newer = \"7 days\"\n", "uv.toml"))["uv release age"].Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(Lines(Tool(Toolchain.Uv, "0.11.21", variables: new() { ["UV_EXCLUDE_NEWER"] = "P7D" }))["uv release age"].Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(Lines(Tool(Toolchain.Uv, "0.9.0"))["uv release age"].Fix!.Instruction, Does.StartWith("uv self update"));
    }

    [Test]
    public void Go_warns_only_when_the_checksum_database_is_off()
    {
        Assert.That(Lines(Tool(Toolchain.Go, "1.25.3"))["Go checksums"].Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(Lines(Tool(Toolchain.Go, "1.25.3", "GOSUMDB=off\n", "env"))["Go checksums"].Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(Lines(Tool(Toolchain.Go, "1.25.3", variables: new() { ["GOSUMDB"] = "off" }))["Go checksums"].Status, Is.EqualTo(DoctorStatus.Warn));
    }

    [Test]
    public void Cargo_reads_its_age_under_registry()
    {
        var lines = Lines(Tool(Toolchain.Cargo, null, "[registry]\nglobal-min-publish-age = \"7 days\"\n", "config.toml"));

        Assert.That(lines["Cargo release age"].Detail, Does.Contain("7 days"));
        Assert.That(Lines(Tool(Toolchain.Cargo, null))["Cargo release age"].Status, Is.EqualTo(DoctorStatus.Warn));
    }

    [Test]
    public void Gradle_warns_when_the_user_weakens_verification()
    {
        Assert.That(Lines(Tool(Toolchain.Gradle, null, "org.gradle.dependency.verification=lenient\n", "gradle.properties"))["Gradle verification"].Status,
            Is.EqualTo(DoctorStatus.Warn));
        Assert.That(Lines(Tool(Toolchain.Gradle, null))["Gradle verification"].Status, Is.EqualTo(DoctorStatus.Ok));
    }

    [Test]
    public void Lines_name_no_path_and_copy_a_command()
    {
        var all = Doctor.SupplyChain(Enum.GetValues<Toolchain>().Select(t => Tool(t, null, "x=y\n", "file"))).ToArray();

        Assert.That(all.Select(c => c.Tool()).Distinct(), Is.EquivalentTo(Enum.GetValues<Toolchain>()));
        foreach (var check in all)
        {
            Assert.That(check.Name + check.Detail + check.Fix?.Instruction, Does.Not.Contain("alice"));
            Assert.That((check.Surface, check.ForDevelopers), Is.EqualTo((true, true)));
            if (check.Fix is not null)
                Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.CopyCommand));
        }
    }

    [Test]
    public void Warnings_of_one_kind_group_on_Home()
    {
        var checks = Doctor.SupplyChain([Tool(Toolchain.Npm, "11.0.0"), Tool(Toolchain.Pip, "26.1"), Tool(Toolchain.Bun, null)]).ToArray();

        Assert.That(checks.Where(c => c.Name.EndsWith("release age", StringComparison.Ordinal)).Select(c => c.Kind).Distinct().Count(), Is.EqualTo(1));
    }

    [TestCase("12.2.3", "12.2.3")]
    [TestCase("v1.25.3", "1.25.3")]
    [TestCase("26.1", "26.1")]
    [TestCase("4.19.0-rc.1", "4.19.0")]
    [TestCase("11", "11.0")]
    [TestCase("go1.25", null)]
    [TestCase(null, null)]
    public void Versions_parse_without_their_suffix(string? text, string? expected) =>
        Assert.That(ToolVersion.Parse(text)?.ToString(), Is.EqualTo(expected));

    [Test]
    public void NuGet_safeguards_take_the_last_entry_of_a_source()
    {
        var safeguards = NuGetConfig.Safeguards(GatedNuGet)!;

        Assert.That(safeguards.Sources, Is.EqualTo(new[] { ("nuget.org", 168) }));
        Assert.That(safeguards.SignatureValidationMode, Is.EqualTo("require"));
        Assert.That(NuGetConfig.Safeguards("not xml"), Is.Null);
    }
}

static class ToolLines
{
    /// <summary>The toolchain a line is about, from its name.</summary>
    public static Toolchain Tool(this DoctorCheck check) => check.Name.Split(' ')[0] switch
    {
        "npm" => Toolchain.Npm,
        "pnpm" => Toolchain.Pnpm,
        "Yarn" => Toolchain.Yarn,
        "Bun" => Toolchain.Bun,
        "NuGet" => Toolchain.NuGet,
        "pip" => Toolchain.Pip,
        "uv" => Toolchain.Uv,
        "Go" => Toolchain.Go,
        "Cargo" => Toolchain.Cargo,
        "Gradle" => Toolchain.Gradle,
        var other => throw new AssertionException(other),
    };
}
