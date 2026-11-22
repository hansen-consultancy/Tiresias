using System.Text;
using System.Text.Json;
using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class DevcontainerTests
{
    const string Canary = "canary-7f3a9c";

    static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    static readonly string Devcontainer = $$"""
        // JSON with comments, as VS Code writes it
        {
          "name": "shop",
          "image": "mcr.microsoft.com/devcontainers/dotnet:8.0",
          "containerEnv": {
            "OPENAI_API_KEY": "sk-{{Canary}}",
            "GITHUB_TOKEN": "${localEnv:GITHUB_TOKEN}",
            "ASPNETCORE_ENVIRONMENT": "Development",
            "DATABASE_URL": "postgres://app:{{Canary}}@db:5432/shop",
            "CACHE_URL": "redis://cache:6379",
            "EMPTY_SECRET": "",
          },
          "remoteEnv": { "STRIPE_SECRET": "{{Canary}}", "PATH": "${containerEnv:PATH}:/tools" },
          "runArgs": ["--init", "-e", "SMTP_PASSWORD={{Canary}}", "-e", "FROM_HOST_TOKEN", "--env=SIGNING_KEY={{Canary}}", "--env-file", ".devcontainer/devcontainer.env", "--env-file=${localWorkspaceFolder}/.env"],
          "customizations": { "vscode": { "settings": { "API_KEY": "{{Canary}}" } } },
        }
        """;

    static DevcontainerScan.Contents Scanned => DevcontainerScan.Read(Bytes(Devcontainer));

    static string[] Secret(IEnumerable<ScannedName> names) => [.. names.Where(n => n.LooksSecret).Select(n => n.Shown)];

    [Test]
    public void A_devcontainer_file_yields_its_secret_looking_literals_and_skips_references()
    {
        var sources = Scanned.Sources.ToDictionary(s => s.Where, s => s.Names);
        Assert.Multiple(() =>
        {
            Assert.That(sources.Keys, Is.EquivalentTo(new[] { "containerEnv", "remoteEnv", "runArgs" }), "customizations are not the container's environment");
            Assert.That(Secret(sources["containerEnv"]), Is.EqualTo(new[] { "OPENAI_API_KEY", "DATABASE_URL (password in URL)" }));
            Assert.That(Secret(sources["remoteEnv"]), Is.EqualTo(new[] { "STRIPE_SECRET" }));
            Assert.That(Secret(sources["runArgs"]), Is.EqualTo(new[] { "SMTP_PASSWORD", "SIGNING_KEY" }), "-e NAME alone passes the host's value");
            Assert.That(Scanned.EnvFiles, Is.EqualTo(new[] { ".devcontainer/devcontainer.env", "${localWorkspaceFolder}/.env" }));
        });
    }

    [Test]
    public void No_value_reaches_the_facts_or_the_findings()
    {
        var file = new DevcontainerFile(@"C:\src\shop\.devcontainer\devcontainer.json", @"C:\src\shop",
            [.. Scanned.Sources, new(".devcontainer/devcontainer.env", NameScan.EnvLines(Bytes($"DB_PASSWORD={Canary}\n")))]);
        var check = Doctor.Devcontainers([file], null).Single();
        var everything = JsonSerializer.Serialize(file) + check.Name + check.Detail + check.Fix!.Instruction + ((InjectAtRunTime)check.Fix).Commands;
        Assert.That(everything, Does.Not.Contain(Canary));
    }

    [Test]
    public void The_scanned_bytes_are_cleared()
    {
        var buffer = Bytes($"API_KEY={Canary}\n");
        var names = NameScan.Consume(buffer, NameScan.EnvLines);
        Assert.That(names.Single().Name, Is.EqualTo("API_KEY"));
        Assert.That(buffer, Is.All.EqualTo(0));
    }

    [Test]
    public void A_stream_is_read_past_its_byte_order_mark_and_a_huge_one_not_at_all()
    {
        using var small = new MemoryStream([.. "\uFEFF"u8, .. Bytes("API_KEY=x")]);
        Assert.That(NameScan.Read(small, NameScan.EnvLines).Single().Name, Is.EqualTo("API_KEY"));
        using var huge = new MemoryStream(Bytes("API_KEY=x\n" + new string('#', NameScan.MaxBytes)));
        Assert.That(NameScan.Read(huge, NameScan.EnvLines), Is.Empty);
    }

    [TestCase("{ \"containerEnv\": { \"API_KEY\": ")]
    [TestCase("[1, 2]")]
    [TestCase("")]
    [TestCase("not json")]
    public void Malformed_JSON_has_no_names_and_throws_nothing(string json) =>
        Assert.That(DevcontainerScan.Read(Bytes(json)).Sources, Is.Empty);

    [Test]
    public void Env_lines_take_comments_export_quotes_and_odd_lines()
    {
        var names = NameScan.EnvLines(Bytes("# comment\r\nexport API_TOKEN=\"abc\"\r\n\nNOT A LINE\n=nameless\nHOME_PATH=/home/alice\nKEY_FILE=C:\\keys\\a.pem\nWINDOWS_TOKEN=%TOKEN%\nEMPTY_KEY=''\n"));
        Assert.Multiple(() =>
        {
            Assert.That(names.Select(n => n.Name), Is.EqualTo(new[] { "API_TOKEN", "HOME_PATH", "KEY_FILE", "WINDOWS_TOKEN", "EMPTY_KEY" }));
            Assert.That(Secret(names), Is.EqualTo(new[] { "API_TOKEN" }), "a path to a key is not the key; a reference and an empty value hold nothing");
        });
    }

    [TestCase("postgres://u:p@h/db", true)]
    [TestCase("postgres://h/db", false)]
    [TestCase("https://alice@example.com/repo", false)]
    [TestCase("https://example.com/a@b:c", false)]
    [TestCase("amqp://u:@h", false)]
    public void A_password_in_a_URL_is_seen_under_any_name(string value, bool password)
    {
        var name = NameScan.Facts("CONN", Bytes(value));
        Assert.That((name.HasPassword, name.LooksSecret), Is.EqualTo((password, password)));
    }

    [TestCase(@"C:\src\shop\.devcontainer\devcontainer.json", @"C:\src\shop")]
    [TestCase(@"C:\src\shop\.devcontainer\api\devcontainer.json", @"C:\src\shop")]
    [TestCase(@"C:\src\shop\.devcontainer.json", @"C:\src\shop")]
    [TestCase(@"C:\src\shop\samples\devcontainer.json", null)]
    [Platform("Win")]
    public void The_workspace_is_the_folder_VS_Code_opens(string path, string? workspace) =>
        Assert.That(DevcontainerScan.Workspace(path), Is.EqualTo(workspace));

    [Test, Platform("Win")]
    public void An_env_file_is_looked_for_against_the_workspace_then_the_file_s_folder()
    {
        Assert.That(DevcontainerScan.EnvFileCandidates("devcontainer.env", @"C:\src\shop", @"C:\src\shop\.devcontainer"),
            Is.EqualTo(new[] { @"C:\src\shop\devcontainer.env", @"C:\src\shop\.devcontainer\devcontainer.env" }));
        Assert.That(DevcontainerScan.EnvFileCandidates("${localWorkspaceFolder}/.env", @"C:\src\shop", @"C:\src\shop\.devcontainer"),
            Is.EqualTo(new[] { @"C:\src\shop\.env" }));
    }

    [Test]
    public void A_file_with_secrets_is_a_finding_whose_fix_hands_them_in_at_start()
    {
        var check = Doctor.Devcontainers([new(@"C:\src\shop\.devcontainer\devcontainer.json", @"C:\src\shop", Scanned.Sources)], null).Single();
        var fix = (InjectAtRunTime)check.Fix!;
        Assert.Multiple(() =>
        {
            Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
            Assert.That(check.Kind, Is.EqualTo("devcontainer files holding secrets"));
            Assert.That(FindingView.Moves(check), Is.EqualTo("E5/C3 → E4/C1"));
            Assert.That(check.Detail, Does.StartWith("containerEnv: OPENAI_API_KEY, DATABASE_URL (password in URL); remoteEnv: STRIPE_SECRET; runArgs: SMTP_PASSWORD, SIGNING_KEY: in plain text"));
            Assert.That(fix.Names, Is.EqualTo(new[] { "OPENAI_API_KEY", "DATABASE_URL", "STRIPE_SECRET", "SMTP_PASSWORD", "SIGNING_KEY" }));
            Assert.That(fix.Commands.Split('\n'), Does.Contain("tir env set OPENAI_API_KEY --folder \"C:\\src\\shop\"").And.Contain("tir run -- code ."));
            Assert.That(fix.Instruction, Does.Contain("${localEnv:NAME}").And.Contain("quit VS Code"));
            Assert.That(FindingView.Button(fix), Is.EqualTo((FixAction.CopyCommand, "Finding_FixCopy")));
        });
    }

    [Test]
    public void A_file_without_secrets_reports_nothing() =>
        Assert.That(Doctor.Devcontainers([new("a", "b", DevcontainerScan.Read(Bytes("""{ "containerEnv": { "TOKEN": "${localEnv:TOKEN}" } }""")).Sources)], null), Is.Empty);

    [TestCase("{}", true, true)]
    [TestCase("""{ "dev.containers.gitCredentialHelperConfigLocation": "none", /* off */ "dev.containers.dockerCredentialHelper": false, }""", false, false)]
    [TestCase("""{ "dev.containers.gitCredentialHelperConfigLocation": "global", "editor.fontSize": 14 }""", true, true)]
    [TestCase("{ broken", true, true)]
    public void Forwarding_is_on_unless_the_settings_turn_it_off(string settings, bool git, bool docker) =>
        Assert.That(DevcontainerScan.Forwarding(Bytes(settings)), Is.EqualTo(new DevcontainerForwarding(git, docker)));

    [Test]
    public void Forwarding_is_a_finding_while_on_and_a_passing_line_when_off()
    {
        var on = Doctor.Devcontainers([], new(true, false)).Single();
        var off = Doctor.Devcontainers([], new(false, false)).Single();
        Assert.Multiple(() =>
        {
            Assert.That(on.IsFinding);
            Assert.That(on.Detail, Does.Contain("forwards your git credentials into every container"));
            Assert.That(on.Fix!.Instruction, Does.Contain("\"dev.containers.gitCredentialHelperConfigLocation\": \"none\""));
            Assert.That(FindingView.Button(on.Fix), Is.EqualTo((FixAction.OpenGuide, "Finding_FixReachGuide")));
            Assert.That(off.IsFinding, Is.False);
            Assert.That(Doctor.Devcontainers([], null), Is.Empty, "Dev Containers not installed");
        });
    }
}
