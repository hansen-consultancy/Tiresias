using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class CliSignInTests
{
    const string Token = "gho_s3cr3tNeverShown";
    const string Hosts = @"C:\Users\alice\AppData\Roaming\GitHub CLI\hosts.yml";
    const string Profile = @"C:\Users\alice\.azure\azureProfile.json";

    static DoctorCheck[] Checks(string? hosts = null, string? profile = null, string? app = null) =>
        [.. Doctor.CliSignIns(new(hosts is null ? null : new(Hosts, hosts), profile is null ? null : new(Profile, profile)), app)];

    static readonly Position Minted = new(Exposure.ShortLived, Control.Approved);

    [Test]
    public void Gh_signed_in_with_the_keyring_is_a_finding_that_adds_a_GitHub_App()
    {
        var check = Checks("github.com:\n    git_protocol: https\n    users:\n        alice:\n    user: alice\n").Single();

        Assert.That(check.Name, Is.EqualTo("gh signed in"));
        Assert.That(check.Detail, Does.Contain("alice on github.com").And.Contain("Windows Credential Manager"));
        Assert.That((check.Now, check.Better), Is.EqualTo(((Position?)Position.Plaintext, (Position?)Minted)));
        Assert.That(check.Fix, Is.EqualTo(new RunThroughExec("gh", null)));
        Assert.That(((RunThroughExec)check.Fix!).Setup, Is.EqualTo(new AddService(ServiceKind.Http, "https://api.github.com")));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.AddService));
        Assert.That(HomeAreas.Of(check.Fix), Is.EqualTo(HomeArea.Services));
    }

    [Test]
    public void With_a_GitHub_App_service_the_fix_is_the_exec_command()
    {
        var check = Checks("github.com:\n    user: alice\n", app: "github").Single();

        Assert.That(check.Fix!.Instruction, Is.EqualTo("tir exec github --purpose \"<why>\" -- gh <args>"));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.CopyCommand));
    }

    [Test]
    public void A_token_in_hosts_yml_says_so_and_is_never_shown()
    {
        var checks = Checks($"github.com:\r\n    oauth_token: {Token}\r\n    git_protocol: https\r\n    user: alice\r\nghe.example.com:\r\n    users:\r\n        bob:\r\n            oauth_token: {Token}\r\n    user: bob\r\n");

        var check = checks.Single();
        Assert.That(check.Detail, Does.Contain("alice on github.com, bob on ghe.example.com").And.Contain($"in plain text in {Hosts}"));
        Assert.That(check.Name + check.Detail + check.Fix!.Instruction, Does.Not.Contain(Token));
    }

    [TestCase("")]
    [TestCase("github.com:\n    git_protocol: https\n")]
    [TestCase("{}\n")]
    [TestCase("not: [valid yaml\n")]
    public void Gh_signed_out_or_unreadable_is_no_finding(string hosts) =>
        Assert.That(Checks(hosts), Is.Empty);

    [Test]
    public void A_user_named_in_the_users_map_alone_is_not_signed_in() =>
        Assert.That(Checks("github.com:\n    users:\n        user: alice\n"), Is.Empty);

    [Test]
    public void Az_signed_in_is_a_finding_without_a_fix()
    {
        var check = Checks(profile: "\uFEFF{\"installationId\":\"x\",\"subscriptions\":[{\"id\":\"1\",\"user\":{\"name\":\"alice@example.com\",\"type\":\"user\"}},{\"id\":\"2\",\"user\":{\"name\":\"ALICE@example.com\",\"type\":\"user\"}}]}").Single();

        Assert.That(check.Name, Is.EqualTo("az signed in"));
        Assert.That(check.Detail, Does.Contain("signed in as alice@example.com,").And.Contain("az logout"));
        Assert.That((check.Fix, check.Now, check.Better), Is.EqualTo(((DoctorFix?)null, (Position?)Position.Plaintext, (Position?)null)));
        Assert.That(check.IsFinding, Is.True);
    }

    [TestCase("{\"subscriptions\":[]}")]
    [TestCase("{}")]
    [TestCase("{\"subscriptions\":[{\"user\":null}]}")]
    [TestCase("not json")]
    [TestCase("[]")]
    [TestCase("null")]
    [TestCase("\"x\"")]
    [TestCase("{\"subscriptions\":[1,\"x\",{\"user\":{\"name\":3}}]}")]
    public void Az_signed_out_or_unreadable_is_no_finding(string profile) =>
        Assert.That(Checks(profile: profile), Is.Empty);

    [Test]
    public void Neither_file_is_no_finding() => Assert.That(Checks(), Is.Empty);
}
