using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class AttackSurfaceTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);
    static readonly ExtensionHost Code = new("VS Code", "Code.exe", "code");
    static readonly ExtensionHost Cursor = new("Cursor", "Cursor.exe", "cursor");
    const string CodeExe = @"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe";
    const string CursorExe = @"C:\Users\alice\AppData\Local\Programs\cursor\Cursor.exe";

    static InstalledExtension Extension(string id, string? publisher = "Acme", int updatedDaysAgo = 30, ExtensionHost? host = null) =>
        new(host ?? Code, id, "1.0.0", publisher, Now.AddDays(-updatedDaysAgo));

    static CredentialUse Use(string program, string service, int daysAgo = 3) => new(program, service, Now.AddDays(-daysAgo));

    static DoctorCheck[] Run(IEnumerable<InstalledExtension>? extensions = null, IEnumerable<StartupEntry>? startup = null,
        IEnumerable<CredentialUse>? uses = null, IEnumerable<string>? blocked = null) =>
        [.. Doctor.AttackSurface(extensions ?? [], startup ?? [], uses ?? [], blocked ?? [], Now)];

    [Test]
    public void An_unknown_publishers_extension_in_a_host_that_used_a_credential_is_a_finding_with_a_fix_and_no_position()
    {
        var check = Run([Extension("acme.helper", publisher: null)], uses: [Use(CodeExe, "github")]).Single();

        Assert.That(check.Name, Is.EqualTo("acme.helper in VS Code (unknown publisher)"));
        Assert.That(check.Detail, Does.Contain("github"));
        Assert.That(check.Fix, Is.EqualTo(new RemoveExtension(Code, "acme.helper")));
        Assert.That(check.Fix!.Instruction, Is.EqualTo("code --uninstall-extension acme.helper"));
        Assert.That(check.Now, Is.Null);
        Assert.That(check.IsFinding, Is.True);
        Assert.That(check.Kind, Is.EqualTo(Doctor.ExtensionKind));
    }

    [Test]
    public void An_extension_unchanged_for_two_years_is_doubted_too()
    {
        var check = Run([Extension("acme.old", updatedDaysAgo: 800)], uses: [Use(CodeExe, "openai")]).Single();

        Assert.That(check.Name, Does.EndWith("(not updated in 2 years)"));
    }

    [Test]
    public void An_extension_in_a_host_that_used_no_credential_in_90_days_is_not_a_finding()
    {
        Assert.That(Run([Extension("acme.helper", publisher: null)], uses: [Use(CodeExe, "github", daysAgo: 120), Use(CursorExe, "github")]), Is.Empty);
    }

    [Test]
    public void A_known_recent_extension_is_not_a_finding()
    {
        Assert.That(Run([Extension("acme.helper")], uses: [Use(CodeExe, "github")]), Is.Empty);
    }

    [Test]
    public void Extensions_in_the_host_that_reaches_more_come_first()
    {
        var checks = Run([Extension("acme.a", publisher: null), Extension("acme.b", publisher: null, host: Cursor)],
            uses: [Use(CodeExe, "github"), Use(CursorExe, "github"), Use(CursorExe, "openai")]);

        Assert.That(checks.Select(c => c.Name), Is.EqualTo(new[] { "acme.b in Cursor (unknown publisher)", "acme.a in VS Code (unknown publisher)" }));
    }

    [Test]
    public void A_version_update_keeps_a_dismissal_and_a_new_reason_brings_it_back()
    {
        var uses = new[] { Use(CodeExe, "github") };
        var before = Run([Extension("acme.helper", publisher: null)], uses: uses).Single();
        var dismissals = Dismissals.Empty.Dismiss(before, "I wrote it", Now);

        var updated = Run([Extension("acme.helper", publisher: null) with { Version = "2.0.0" }], uses: uses).Single();
        var stale = Run([Extension("acme.helper", publisher: null, updatedDaysAgo: 800)], uses: uses).Single();

        Assert.That(dismissals.For(updated), Is.Not.Null);
        Assert.That(dismissals.For(stale), Is.Null);
    }

    [TestCase("acme.helper", true)]
    [TestCase("ms-dotnettools.csdevkit", true)]
    [TestCase("acme.helper & calc", false)]
    [TestCase("acme", false)]
    [TestCase("-acme.helper", false)]
    [TestCase("acme.helper\"", false)]
    public void Only_a_plain_marketplace_id_reaches_the_hosts_command(string id, bool safe) =>
        Assert.That(RemoveExtension.IsSafeId(id), Is.EqualTo(safe));

    [Test]
    public void An_extension_whose_id_isnt_plain_raises_no_command()
    {
        Assert.That(Run([Extension("acme.x&calc", publisher: null)], uses: [Use(CodeExe, "github")]), Is.Empty);
    }

    [Test]
    public void An_unsigned_startup_program_is_a_finding_saying_what_it_reached()
    {
        const string tool = @"C:\Users\alice\tools\sync.exe";
        var checks = Run(startup: [new("Sync", "Run key", tool, Signed: false), new("Signed", "Run key", @"C:\a\b.exe", Signed: true), new("Windows", "Run key", @"C:\Windows\x.exe", Signed: null)],
            uses: [Use(tool, "storage")]);

        var check = checks.Single();
        Assert.That(check.Name, Is.EqualTo("Sync starts at log-on unsigned"));
        Assert.That(check.Detail, Does.Contain("storage"));
        Assert.That(check.Fix, Is.EqualTo(new RevealFile(tool)));
        Assert.That(check.Kind, Is.EqualTo(Doctor.UnsignedStartupKind));
    }

    [Test]
    public void A_blocked_program_comes_first_as_a_failure_and_isnt_reported_twice()
    {
        const string bad = @"C:\Users\alice\AppData\Roaming\x\bad.exe";
        var checks = Run([Extension("acme.helper", publisher: null)], [new("Bad", "Run key", bad, Signed: false)], [Use(CodeExe, "github")], [bad]);

        Assert.That(checks[0].Status, Is.EqualTo(DoctorStatus.Fail));
        Assert.That(checks[0].Detail, Does.Contain("still starts at log-on"));
        Assert.That(checks[0].Fix, Is.EqualTo(new RevealFile(bad)));
        Assert.That(checks.Count(c => c.Fix is RevealFile), Is.EqualTo(1));
    }

    [Test]
    public void Surface_findings_get_their_own_buttons()
    {
        Assert.That(FindingView.Button(new RemoveExtension(Code, "acme.helper"))?.Action, Is.EqualTo(FixAction.RemoveExtension));
        Assert.That(FindingView.Button(new RemoveExtensionByHand(new("Edge", "msedge.exe", null, "edge://extensions"), "Acme"))?.Action, Is.EqualTo(FixAction.CopyCommand));
        Assert.That(FindingView.Button(new RevealFile(@"C:\x.exe"))?.Action, Is.EqualTo(FixAction.RevealFile));
    }

    [Test]
    public void Credential_uses_come_from_granted_records_with_a_known_program()
    {
        string[] lines =
        [
            """{"prevHash":"0","time":"2026-11-18T10:00:00Z","kind":"Allow","service":"github","process":"C:\\a\\Code.exe (pid 7)"}""",
            """{"prevHash":"0","time":"2026-11-18T10:00:00Z","kind":"Deny","service":"openai","process":"C:\\a\\Code.exe (pid 7)"}""",
            """{"prevHash":"0","time":"2026-11-18T10:00:00Z","kind":"Allow","service":"openai","process":"pid 9"}""",
            """{"prevHash":"0","time":"2026-11-18T10:00:00Z","kind":"Allow","consumer":"environment","service":"tool","reason":"API_KEY","process":"C:\\a\\tool.exe"}""",
            "not json",
        ];

        Assert.That(Doctor.CredentialUses(lines), Is.EqualTo(new[]
        {
            new CredentialUse(@"C:\a\Code.exe", "github", new(2026, 11, 18, 10, 0, 0, TimeSpan.Zero)),
            new CredentialUse(@"C:\a\tool.exe", "sealed environment variables", new(2026, 11, 18, 10, 0, 0, TimeSpan.Zero)),
        }));
    }

    [Test]
    public void Extensions_are_read_from_the_hosts_metadata()
    {
        const string json = """
            [
              {"identifier":{"id":"ms-python.python"},"version":"2026.1.0","metadata":{"installedTimestamp":1763546400000,"source":"gallery","publisherId":"p1","publisherDisplayName":"Microsoft"}},
              {"identifier":{"id":"acme.local"},"version":"0.1.0","metadata":{"installedTimestamp":1763546400000,"source":"vsix"}},
              {"identifier":{"id":"acme.old"},"version":"1.0.0"},
              {"version":"9"}
            ]
            """;

        var found = Doctor.Extensions(Code, json).ToArray();

        Assert.That(found.Select(e => (e.Id, e.Publisher)), Is.EqualTo(new (string, string?)[] { ("ms-python.python", "Microsoft"), ("acme.local", null), ("acme.old", "acme") }));
        Assert.That(found[0].Updated, Is.EqualTo(DateTimeOffset.FromUnixTimeMilliseconds(1763546400000)));
        Assert.That(Doctor.Extensions(Code, "{broken"), Is.Empty);
    }

    [TestCase("-99999999999999999")]
    [TestCase("99999999999999999")]
    public void A_timestamp_out_of_range_reads_as_unknown(string stamp)
    {
        var json = $$$"""[{"identifier":{"id":"acme.x"},"metadata":{"installedTimestamp":{{{stamp}}},"publisherId":"p"}}]""";

        Assert.That(Doctor.Extensions(Code, json).Single().Updated, Is.Null);
    }

    [TestCase("\"C:\\Program Files\\App\\app.exe\" --tray", @"C:\Program Files\App\app.exe")]
    [TestCase(@"C:\Tools\sync.exe /background", @"C:\Tools\sync.exe")]
    [TestCase(@"C:\Program Files\App\app.EXE", @"C:\Program Files\App\app.EXE")]
    [TestCase("rundll32 shell32.dll,Control_RunDLL", "rundll32")]
    [TestCase("  ", null)]
    public void A_run_key_command_names_its_executable(string command, string? expected) =>
        Assert.That(Doctor.ExecutableIn(command), Is.EqualTo(expected));

    [Test]
    public void Blocked_paths_come_from_the_blocklist_file()
    {
        Assert.That(Doctor.BlockedPaths("""{"v":1,"lockedDown":false,"programs":[{"path":"C:\\x\\bad.exe","sha256":null,"since":"2026-11-01T00:00:00Z"}]}"""),
            Is.EqualTo(new[] { @"C:\x\bad.exe" }));
        Assert.That(Doctor.BlockedPaths(null), Is.Empty);
        Assert.That(Doctor.BlockedPaths("[1]"), Is.Empty);
    }

    [Test]
    public void The_blocklist_format_read_here_is_the_one_the_app_writes()
    {
        var list = Blocklist.Empty.Escalate(@"C:\x\bad.exe", null, Now);
        Assert.That(Doctor.BlockedPaths(list.ToJson()), Is.EqualTo(new[] { @"C:\x\bad.exe" }));
    }
}
