using System.Text;
using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class WslTests
{
    const string Canary = "canary-5c03ae";

    static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    static ReachFacts Facts(params string[] distributions) =>
        new([], [.. distributions.Select(d => new WslDistribution(d, $@"C:\wsl\{d}\ext4.vhdx", ["your account"]))], HyperVAccess.NotInstalled);

    static DoctorCheck[] Checks(ReachFacts facts, ReachContents? contents) => [.. Doctor.WslContents(facts, contents)];

    [Test]
    public void Aws_credentials_name_the_profiles_that_hold_a_secret()
    {
        var text = $"[default]\naws_access_key_id = AKIA\naws_secret_access_key = {Canary}\n\n[sso]\nsso_start_url = https://example.com\n[ci]\r\naws_session_token=\"{Canary}\"\r\n[empty]\naws_secret_access_key =\n";
        Assert.That(HomeScan.IniSections(Bytes(text)), Is.EqualTo(new[] { "default", "ci" }));
        Assert.That(HomeScan.Names(HomeFileKind.IniSections, Bytes("[sso]\nregion = eu-west-1\n")), Is.Null);
    }

    [Test]
    public void Docker_config_names_registries_with_a_stored_login_only()
    {
        var json = $$"""
            { "auths": { "registry.example.com": { "auth": "{{Canary}}" }, "helper.example.com": {}, "token.example.com": { "identitytoken": "{{Canary}}" }, "blank.example.com": { "auth": "" } },
              "credsStore": "desktop" }
            """;
        Assert.That(HomeScan.DockerAuths(Bytes(json)), Is.EqualTo(new[] { "registry.example.com", "token.example.com" }));
        Assert.That(HomeScan.DockerAuths(Bytes("{ not json")), Is.Empty);
        Assert.That(HomeScan.Names(HomeFileKind.DockerAuths, Bytes("""{ "credsStore": "desktop" }""")), Is.Null);
    }

    [TestCase("//registry.npmjs.org/:_authToken=" + Canary, true)]
    [TestCase("//registry.npmjs.org/:_authToken=${NPM_TOKEN}", false)]
    [TestCase("_auth = " + Canary, true)]
    [TestCase("registry=https://registry.example.com/", false)]
    [TestCase("[pypi]\nusername = __token__\npassword = " + Canary, true)]
    [TestCase("github.com:\n    oauth_token: gho_" + Canary + "=\n    user: alice", true)]
    [TestCase("github.com:\n    user: alice\n    git_protocol: https", false)]
    [TestCase("# _authToken=" + Canary, false)]
    public void Token_lines(string text, bool token) => Assert.That(HomeScan.HasToken(Bytes(text)), Is.EqualTo(token));

    [Test]
    public void Env_files_name_their_secret_looking_variables()
    {
        Assert.That(HomeScan.Names(HomeFileKind.Env, Bytes($"OPENAI_API_KEY={Canary}\nPORT=8080\nGH_TOKEN=$GH_TOKEN\n")), Is.EqualTo(new[] { "OPENAI_API_KEY" }));
        Assert.That(HomeScan.Names(HomeFileKind.Env, Bytes("PORT=8080\n")), Is.Null);
    }

    [TestCase("id_ed25519", true)]
    [TestCase("id_rsa", true)]
    [TestCase("id_ed25519.pub", false)]
    [TestCase("known_hosts", false)]
    public void Ssh_keys(string name, bool key) => Assert.That(HomeScan.IsSshKey(name), Is.EqualTo(key));

    [Test]
    public void Running_reads_either_encoding_and_keeps_registered_names_only()
    {
        string[] registered = ["Ubuntu", "Debian", "docker-desktop"];
        Assert.That(HomeScan.Running(Encoding.Unicode.GetBytes("Ubuntu\r\ndocker-desktop\r\n"), registered), Is.EqualTo(new[] { "Ubuntu", "docker-desktop" }));
        Assert.That(HomeScan.Running(Bytes("ubuntu\nUbuntu\n"), registered), Is.EqualTo(new[] { "ubuntu" }));
        Assert.That(HomeScan.Running(Encoding.Unicode.GetBytes("There are no running distributions.\r\n"), registered), Is.Empty);
        Assert.That(HomeScan.Running([], registered), Is.Empty);
    }

    [Test]
    public void A_running_distribution_with_credential_files_is_a_finding()
    {
        var contents = new ReachContents(null,
        [
            new("Ubuntu",
            [
                new("/home/alice/.aws/credentials", ["default", "prod"]),
                new("/home/alice/.ssh/id_ed25519", []),
                new("/home/alice/.bash_history", [], MayHold: true),
            ]),
            new("Alpine", [new("/root/.bash_history", [], MayHold: true)]),
        ]);
        var checks = Checks(Facts("Ubuntu", "Alpine", "Debian", "docker-desktop"), contents);

        var ubuntu = checks.Single(c => c.Name == "wsl Ubuntu");
        Assert.That(ubuntu.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(ubuntu.Detail, Does.StartWith("/home/alice/.aws/credentials [default, prod], /home/alice/.ssh/id_ed25519, /home/alice/.bash_history (may hold commands with tokens): in this running distribution"));
        Assert.That(ubuntu.Fix, Is.EqualTo(new ReachGuide(ReachTopic.Wsl, Distribution: "Ubuntu")));
        Assert.That(ubuntu.Fix!.Instruction, Does.Contain("tir run --only NAME -- wsl -d Ubuntu <command>"));
        Assert.That((ubuntu.Now, ubuntu.Better), Is.EqualTo((Position.Plaintext, Position.SealedApproved)));
        Assert.That(checks.Select(c => c.Name), Has.None.EqualTo("wsl Alpine"), "history alone is no finding");
        Assert.That(checks.Single(c => c.Name == Doctor.WslContentsCheck).Detail,
            Is.EqualTo("looked inside 2 running distributions; Debian isn't running, so it was not read: opening its files would start it"));
    }

    [Test]
    public void A_hostile_distribution_name_stays_out_of_the_command()
    {
        var name = "x\"; calc; \"";
        var check = Checks(Facts(name), new(null, [new(name, [new("/root/.netrc", [])])])).Single();
        Assert.That(check.Fix!.Instruction, Does.Contain("wsl -d <distribution> <command>").And.Not.Contain("calc"));
    }

    [Test]
    public void Nothing_found_and_nothing_asked()
    {
        Assert.That(Checks(Facts("docker-desktop"), null), Is.Empty, "Docker Desktop's own distributions aren't the user's");
        Assert.That(Checks(Facts("Ubuntu"), null).Single().Detail, Does.StartWith("not looked inside: tir doctor --reach"));
        Assert.That(Checks(Facts("Ubuntu"), new(null)).Single().Detail, Does.StartWith("WSL didn't answer"));
        Assert.That(Checks(Facts("Ubuntu"), new(null, [new("Ubuntu", [])])).Single().Detail,
            Is.EqualTo("looked inside 1 running distribution: no credential files in their homes"));
        Assert.That(Checks(Facts("Ubuntu", "Debian"), new(null, [])).Single().Detail,
            Is.EqualTo("Ubuntu, Debian aren't running, so they were not read: opening their files would start them"));
    }

    [Test]
    public void A_look_counts_when_wsl_answered()
    {
        Assert.That(ReachLook.Counts(new(null, [])), Is.True);
        Assert.That(ReachLook.Counts(new(null, null)), Is.False);
    }

    [Test]
    public void Values_never_reach_a_finding()
    {
        var names = HomeScan.Names(HomeFileKind.IniSections, Bytes($"[{Canary[..3]}]\naws_secret_access_key={Canary}\n"))!;
        var checks = Checks(Facts("Ubuntu"), new(null, [new("Ubuntu", [new("/root/.aws/credentials", names)])]));
        Assert.That(checks.Select(c => c.Detail + c.Fix?.Instruction), Has.None.Contains(Canary));
    }
}
