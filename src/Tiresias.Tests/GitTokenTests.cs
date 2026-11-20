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
        Assert.That(check.Fix!.Instruction, Is.EqualTo($"git -C \"{Repo}\" remote set-url \"origin\" \"https://github.com/example/app.git\""));
        Assert.That((check.Now, check.Better), Is.EqualTo((Position.Plaintext, (Position?)null)));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.CopyCommand));
        AssertNoToken(checks);
    }

    [Test]
    public void A_push_url_is_set_with_push()
    {
        var check = Checks($"[remote \"origin\"]\r\n  url = https://github.com/example/app.git\r\n  pushurl = \"https://x-access-token:{Token}@github.com/example/app.git\"\r\n").Single();

        Assert.That(check.Fix!.Instruction, Does.Contain("remote set-url --push \"origin\" \"https://github.com/example/app.git\""));
    }

    static DoctorCheck Remote(string folder, string remote, string path) =>
        Doctor.GitTokens([new DoctorFile(Path.Combine("C:", "src", folder, ".git", "config"),
            $"[remote \"{remote}\"]\n\turl = https://alice:{Token}@example.com/{path}\n")], null).Single();

    [TestCase("\"https://alice:pa;ss@example.com/app.git\"")]
    [TestCase("\"https://alice:pa;ss@example.com/app.git\" ; a comment")]
    [TestCase("https://alice:\"pa;ss\"@example.com/app.git # a comment")]
    public void A_comment_character_inside_quotes_is_part_of_the_value(string value)
    {
        var check = Checks($"[remote \"origin\"]\n\turl = {value}\n").Single();

        Assert.That(check.Name, Is.EqualTo($"git remote origin in {Repo}"));
        Assert.That(check.Detail, Does.Not.Contain("pa;ss").And.Not.Contain("pa#ss"));
    }

    [Test]
    public void Plain_values_get_a_command() =>
        Assert.That(Remote("my-app_2.0", "up+stream.x", "team/my-app_2.0.git").Fix, Is.Not.Null);

    [Test]
    public void A_space_in_the_repository_path_stays_inside_its_quotes() =>
        Assert.That(Remote("my app", "origin", "app.git").Fix!.Instruction, Does.StartWith($"git -C \"{Path.Combine("C:", "src", "my app")}\" "));

    // Only [A-Za-z0-9/:._@+-] (and a backslash or space inside the repository's path) is offered as a command.
    [TestCase("app", "x\\\"y", "app.git", TestName = "A quote in a remote")]
    [TestCase("app", "origin$x", "app.git", TestName = "A dollar in a remote")]
    [TestCase("x!y", "origin", "app.git", TestName = "A bang in a folder")]
    [TestCase("app", "origin`calc`", "app.git", TestName = "A backtick in a remote")]
    [TestCase("app", "x\\\\", "app.git", TestName = "A trailing backslash in a remote")]
    [TestCase("x\ncalc", "origin", "app.git", TestName = "A newline in a folder")]
    [TestCase("app", "origin", "app?a=1&calc", TestName = "An ampersand in a URL")]
    [TestCase("app", "origin", "app|calc", TestName = "A pipe in a URL")]
    [TestCase("app", "my origin", "app.git", TestName = "A space in a remote")]
    [TestCase("app", "origin", "café.git", TestName = "Non-ASCII in a URL")]
    public void A_value_outside_the_allowlist_is_a_finding_without_a_command(string folder, string remote, string path)
    {
        var check = Remote(folder, remote, path);

        Assert.That(check.Fix, Is.Null);
        Assert.That(check.IsFinding);
    }

    [Test]
    public void A_repository_path_ending_in_a_backslash_gets_no_fix()
    {
        var config = Path.Combine("C:\\", ".git", "config");
        var check = Doctor.GitTokens([new DoctorFile(config, $"[remote \"origin\"]\n\turl = https://alice:{Token}@example.com/app.git\n")], null).Single();

        Assert.That(check.Fix, Is.Null);
        Assert.That(check.IsFinding);
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
