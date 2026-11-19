using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class GitTokenTests
{
    const string Token = "ghp_s3cr3tNeverShown";
    static readonly string Repo = Path.Combine("C:", "src", "app");
    static readonly string Config = Path.Combine(Repo, ".git", "config");

    static DoctorCheck[] Checks(string config, DoctorGitCredentials? credentials = null) =>
        [.. Doctor.GitTokens([new DoctorFile(Config, config)], credentials)];

    static void AssertNoToken(IEnumerable<DoctorCheck> checks)
    {
        foreach (var check in checks)
            Assert.That(check.Name + check.Detail + check.Fix?.Instruction, Does.Not.Contain(Token).And.Not.Contain("alice"));
    }

    [Test]
    public void A_token_in_a_remote_url_is_taken_out_of_it()
    {
        var checks = Checks($"[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://alice:{Token}@github.com/example/app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n");

        var check = checks.Single();
        Assert.That(check.Name, Is.EqualTo($"git remote origin in {Repo}"));
        Assert.That(check.Fix, Is.EqualTo(new RemoveTokenFromRemote(Repo, "origin", "https://github.com/example/app.git")));
        Assert.That(check.Fix!.Instruction, Is.EqualTo($"git -C \"{Repo}\" remote set-url origin https://github.com/example/app.git"));
        Assert.That((check.Now, check.Better), Is.EqualTo((Position.Plaintext, (Position?)null)));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.CopyCommand));
        AssertNoToken(checks);
    }

    [Test]
    public void A_push_url_is_set_with_push()
    {
        var check = Checks($"[remote \"origin\"]\r\n  url = https://github.com/example/app.git\r\n  pushurl = \"https://x-access-token:{Token}@github.com/example/app.git\"\r\n").Single();

        Assert.That(check.Fix!.Instruction, Does.Contain("remote set-url --push origin https://github.com/example/app.git"));
    }

    [TestCase("https://alice@github.com/example/app.git")]
    [TestCase("git@github.com:example/app.git")]
    [TestCase("ssh://git@github.com/example/app.git")]
    [TestCase("https://github.com/example/app.git")]
    public void A_url_without_a_password_is_no_finding(string url) =>
        Assert.That(Checks($"[remote \"origin\"]\n\turl = {url}\n"), Is.Empty);

    [Test]
    public void An_insteadOf_rewrite_holding_a_token_is_a_finding_without_a_fix()
    {
        var checks = Checks($"[url \"https://alice:{Token}@github.com/\"]\n\tinsteadOf = https://github.com/\n");

        Assert.That(checks.Single().Fix, Is.Null);
        Assert.That(checks.Single().Now, Is.EqualTo(Position.Plaintext));
        AssertNoToken(checks);
    }

    [Test]
    public void Stored_credentials_are_counted_by_host_without_their_tokens()
    {
        var credentials = DoctorGitCredentials.From("[credential]\n\thelper = store\n",
            $"https://alice:{Token}@github.com\nhttps://bob:{Token}@dev.example.com\n\n");

        var check = Doctor.GitTokens([], credentials).Single();

        Assert.That(credentials, Is.EqualTo(new DoctorGitCredentials("store", ["github.com", "dev.example.com"])).Using<DoctorGitCredentials>((a, b) => a.Helper == b.Helper && a.StoredHosts.SequenceEqual(b.StoredHosts)));
        Assert.That(check.Detail, Does.StartWith("2 tokens in plain text in .git-credentials for github.com, dev.example.com"));
        Assert.That(check.IsFinding);
        AssertNoToken([check]);
    }

    [Test]
    public void Git_Credential_Manager_is_information_not_a_finding()
    {
        var check = Doctor.GitTokens([], DoctorGitCredentials.From("[credential]\n  helper = manager\n", null)).Single();

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(check.IsFinding, Is.False);
    }

    [Test]
    public void No_git_setup_says_nothing() =>
        Assert.That(Doctor.GitTokens([new DoctorFile(Config, null)], DoctorGitCredentials.From(null, null)), Is.Empty);
}
