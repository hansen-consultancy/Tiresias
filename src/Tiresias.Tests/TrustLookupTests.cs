using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

/// <summary>The opt-in online lookups (docs/attack-surface.md#trust): OSV for global tools, through a seam, cached.</summary>
public class TrustLookupTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 26, 10, 0, 0, TimeSpan.Zero);

    static readonly GlobalTool Acme = new("npm", "acme-cli", "1.2.0");
    static readonly PackageQuery AcmeQuery = new("npm", "acme-cli", "1.2.0");

    [TestCase("dotnet", "NuGet")]
    [TestCase("npm", "npm")]
    [TestCase("pipx", "PyPI")]
    [TestCase("cargo", "crates.io")]
    public void A_tool_is_asked_about_in_its_registry(string manager, string ecosystem) =>
        Assert.That(PackageQuery.Of(new(manager, "acme", "1.0.0")), Is.EqualTo(new PackageQuery(ecosystem, "acme", "1.0.0")));

    [Test]
    public void A_tool_without_a_version_or_from_an_unknown_manager_is_not_asked_about()
    {
        Assert.That(PackageQuery.Of(new("npm", "acme", null)), Is.Null);
        Assert.That(PackageQuery.Of(new("go", "acme", "1.0.0")), Is.Null);
    }

    [Test]
    public void The_request_holds_the_name_ecosystem_and_version_only() =>
        Assert.That(Osv.QueryJson(AcmeQuery), Is.EqualTo("""{"package":{"name":"acme-cli","ecosystem":"npm"},"version":"1.2.0"}"""));

    [Test]
    public void An_advisory_names_the_lowest_fix_above_the_installed_version_for_this_package()
    {
        const string answer = """
            { "vulns": [ { "id": "GHSA-aaaa-bbbb-cccc", "summary": "Prototype pollution",
              "affected": [
                { "package": { "name": "acme-cli", "ecosystem": "npm" },
                  "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "1.1.0" } ] },
                              { "type": "SEMVER", "events": [ { "introduced": "1.2.0" }, { "fixed": "1.10.0" } ] },
                              { "type": "SEMVER", "events": [ { "introduced": "2.0.0" }, { "fixed": "2.0.1" } ] } ] },
                { "package": { "name": "other", "ecosystem": "npm" },
                  "ranges": [ { "type": "SEMVER", "events": [ { "fixed": "1.3.0" } ] } ] } ] } ] }
            """;

        Assert.That(Osv.Parse(answer, AcmeQuery), Is.EqualTo(new[] { new Advisory("GHSA-aaaa-bbbb-cccc", "Prototype pollution", "1.10.0") }));
    }

    [Test]
    public void A_fix_from_a_range_that_does_not_hold_the_installed_version_is_not_the_fix()
    {
        const string answer = """
            { "vulns": [ { "id": "GHSA-1", "affected": [ { "package": { "name": "acme-cli", "ecosystem": "npm" },
              "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "1.2.0" } ] },
                          { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "2.0.1" } ] } ] } ] } ] }
            """;

        Assert.That(Osv.Parse(answer, AcmeQuery)!.Single().Fixed, Is.Null);
    }

    [Test]
    public void Every_range_holding_the_installed_version_must_be_passed()
    {
        const string answer = """
            { "vulns": [ { "id": "GHSA-1", "affected": [
              { "package": { "name": "acme-cli", "ecosystem": "npm" },
                "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "1.0.0" }, { "fixed": "1.3.0" } ] },
                            { "type": "GIT", "events": [ { "introduced": "0" }, { "fixed": "abc123" } ] } ] },
              { "package": { "name": "acme-cli", "ecosystem": "npm" },
                "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "1.1.0" }, { "fixed": "1.5.0" } ] },
                            { "type": "SEMVER", "events": [ { "introduced": "0" }, { "last_affected": "1.0.9" } ] } ] } ] } ] }
            """;

        Assert.That(Osv.Parse(answer, AcmeQuery)!.Single().Fixed, Is.EqualTo("1.5.0"));
    }

    [Test]
    public void An_advisory_without_a_fix_says_so() =>
        Assert.That(Osv.Parse("""{ "vulns": [ { "id": "OSV-1", "affected": [] } ] }""", AcmeQuery), Is.EqualTo(new[] { new Advisory("OSV-1", null, null) }));

    [Test]
    public void An_empty_answer_is_no_advisory_and_a_garbled_one_is_no_answer()
    {
        Assert.That(Osv.Parse("{}", AcmeQuery), Is.Empty);
        Assert.That(Osv.Parse("not json", AcmeQuery), Is.Null);
        Assert.That(Osv.Parse("""{ "vulns": {} }""", AcmeQuery), Is.Null);
    }

    [Test]
    public async Task Only_answers_a_day_old_or_missing_are_asked_again()
    {
        var fresh = new PackageVerdict(new("NuGet", "fresh.tool", "1.0.0"), Now.AddHours(-2), []);
        var old = new PackageVerdict(AcmeQuery, Now.AddDays(-2), []);
        var source = new FakeSource { [AcmeQuery] = [new("GHSA-1", null, "1.3.0")] };

        var lookups = await new TrustLookups([fresh, old]).RefreshAsync([Acme, new("dotnet", "fresh.tool", "1.0.0")], source, Now);

        Assert.That(source.Asked, Is.EqualTo(new[] { AcmeQuery }));
        Assert.That(lookups.For(AcmeQuery), Is.EqualTo(new PackageVerdict(AcmeQuery, Now, [new("GHSA-1", null, "1.3.0")])));
        Assert.That(lookups.For(fresh.Package), Is.EqualTo(fresh));
    }

    [Test]
    public async Task A_source_that_does_not_answer_keeps_the_last_answer_and_an_uninstalled_tool_is_forgotten()
    {
        var old = new PackageVerdict(AcmeQuery, Now.AddDays(-2), [new("GHSA-1", null, null)]);
        var gone = new PackageVerdict(new("PyPI", "gone", "1.0"), Now.AddHours(-1), []);

        var lookups = await new TrustLookups([old, gone]).RefreshAsync([Acme], new FakeSource(), Now);

        Assert.That(lookups.Packages, Is.EqualTo(new[] { old }));
    }

    [Test]
    public void Another_version_has_no_answer_and_names_match_without_case()
    {
        var lookups = new TrustLookups([new(new("NuGet", "Acme.Tool", "1.0.0"), Now, [])]);

        Assert.That(lookups.For(new("NuGet", "acme.tool", "1.0.0")), Is.Not.Null);
        Assert.That(lookups.For(new("NuGet", "acme.tool", "1.0.1")), Is.Null);
    }

    [Test]
    public void The_saved_answers_read_back_and_another_format_is_asked_again()
    {
        var lookups = new TrustLookups([new(AcmeQuery, Now, [new("GHSA-1", "Bad", "1.3.0"), new("OSV-2", null, null)])]);

        Assert.That(TrustLookups.Parse(lookups.ToJson())!.Packages, Is.EqualTo(lookups.Packages));
        Assert.That(TrustLookups.Parse("""{ "version": 99, "packages": [] }"""), Is.Null);
        Assert.That(TrustLookups.Parse("garbled"), Is.Null);
    }

    [Test]
    public void Without_lookups_no_tool_is_called_vulnerable() =>
        Assert.That(Doctor.KnownVulnerabilities([Acme], null), Is.Empty);

    [Test]
    public void A_tool_with_an_advisory_is_a_finding_that_updates_it()
    {
        var lookups = new TrustLookups([new(AcmeQuery, Now, [new("GHSA-1", null, "1.3.0"), new("GHSA-2", null, "1.4.0")])]);

        var finding = Doctor.KnownVulnerabilities([Acme, new("npm", "clean", "1.0.0")], lookups).Single();

        Assert.That(finding.Name, Is.EqualTo("acme-cli 1.2.0 has 2 known vulnerabilities"));
        Assert.That(finding.Detail, Does.Contain("OSV.dev lists GHSA-1, GHSA-2").And.Contain("1.4.0 fixes them all"));
        Assert.That(finding.Fix, Is.EqualTo(Packages.Update(Acme)));
        Assert.That(finding.Fix!.Instruction, Is.EqualTo("npm install --global acme-cli@latest"));
        Assert.That(finding.Kind, Is.EqualTo(Doctor.VulnerableToolKind));
        Assert.That(finding.TrustHides, Is.False);
        Assert.That(FindingView.Button(finding.Fix), Is.EqualTo((FixAction.RunPackage, "Package_UpdateNewest")));
    }

    [Test]
    public void An_advisory_no_version_fixes_suggests_uninstalling()
    {
        var lookups = new TrustLookups([new(new("NuGet", "acme.tool", "2.0.0"), Now, [new("GHSA-1", null, null)])]);

        var finding = Doctor.KnownVulnerabilities([new("dotnet", "acme.tool", "2.0.0")], lookups).Single();

        Assert.That(finding.Fix, Is.EqualTo(new PackageFix(PackageChange.Uninstall, "acme.tool",
            new PackageCommand("dotnet", ["tool", "uninstall", "--global", "acme.tool"]))));
        Assert.That(FindingView.Button(finding.Fix), Is.EqualTo((FixAction.RunPackage, "Package_Uninstall")));
    }

    [Test]
    public void A_tool_the_app_cant_run_a_manager_for_gets_a_command_to_copy()
    {
        var lookups = new TrustLookups([new(new("PyPI", "acme", "1.0"), Now, [new("GHSA-1", null, "1.1")]),
            new(new("crates.io", "acme", "1.0"), Now, [new("GHSA-2", null, null)])]);

        var findings = Doctor.KnownVulnerabilities([new("pipx", "acme", "1.0"), new("cargo", "acme", "1.0")], lookups).ToArray();

        Assert.That(findings.Select(f => f.Fix), Is.EqualTo(new DoctorFix[] { new UninstallGlobalTool("cargo", "acme"), new UpdateGlobalTool("pipx", "acme", "1.1") }));
        Assert.That(findings.Select(f => FindingView.Button(f.Fix)), Is.All.EqualTo((FixAction.CopyCommand, "Finding_FixCopy")));
    }

    [Test]
    public void A_dismissal_made_while_the_fix_was_copied_still_hides_the_runnable_one()
    {
        var finding = Doctor.KnownVulnerabilities([Acme], new TrustLookups([new(AcmeQuery, Now, [new("GHSA-1", null, "1.3.0")])])).Single();
        var dismissals = Dismissals.Empty.Dismiss(finding with { Fix = new UpdateGlobalTool("npm", "acme-cli", "1.3.0") }, "not exposed", Now);

        Assert.That(finding.Fix, Is.InstanceOf<PackageFix>());
        Assert.That(dismissals.For(finding), Is.Not.Null);
    }

    [Test]
    public void A_dismissal_survives_an_update_and_comes_back_for_a_new_advisory()
    {
        static DoctorCheck Finding(string version, params string[] advisories) => Doctor.KnownVulnerabilities([Acme with { Version = version }],
            new TrustLookups([new(AcmeQuery with { Version = version }, Now, [.. advisories.Select(a => new Advisory(a, null, "9.0.0"))])])).Single();
        var dismissals = Dismissals.Empty.Dismiss(Finding("1.2.0", "GHSA-1"), "not exposed", Now);

        Assert.That(dismissals.For(Finding("1.2.1", "GHSA-1")), Is.Not.Null);
        Assert.That(dismissals.For(Finding("1.2.1", "GHSA-1", "GHSA-2")), Is.Null);
    }

    [Test]
    public async Task The_doctor_reads_the_saved_answers_as_a_surface_finding()
    {
        var checks = await Doctor.RunAsync(new Probe(new([new(AcmeQuery, Now, [new("GHSA-1", null, "1.3.0")])])));

        Assert.That(checks.Single(c => c.Kind == Doctor.VulnerableToolKind).Surface, Is.True);
    }

    [Test]
    public void The_details_panel_says_what_was_found_or_why_nothing_was()
    {
        var lookups = new TrustLookups([new(AcmeQuery, Now, [new("GHSA-1", null, "1.3.0")]), new(new("PyPI", "clean", "1.0"), Now, [])]);

        Assert.That(InstalledDetails.Online(Acme, null).Key, Is.EqualTo("Installed_OnlineOff"));
        Assert.That(InstalledDetails.Online(Acme with { Version = null }, lookups).Key, Is.EqualTo("Installed_OnlineCantCheck"));
        Assert.That(InstalledDetails.Online(Acme with { Id = "new" }, lookups).Key, Is.EqualTo("Installed_OnlineNotYet"));
        Assert.That(InstalledDetails.Online(new("pipx", "clean", "1.0"), lookups).Key, Is.EqualTo("Installed_OnlineClean"));
        var (key, arguments) = InstalledDetails.Online(Acme, lookups);
        Assert.That(key, Is.EqualTo("Installed_OnlineVulnerable"));
        Assert.That(arguments[0], Is.EqualTo("OSV.dev"));
        Assert.That(arguments[2], Is.EqualTo("GHSA-1"));
    }

    [Test]
    public void Tir_doctor_surface_says_whether_each_tool_was_checked_online()
    {
        SurfaceInventory Inventory(TrustLookups? lookups) => new([], new(Now, [Acme]), [], [], [], lookups);

        Assert.That(Doctor.InventoryLines(Inventory(null), Now), Does.Contain("  npm: acme-cli 1.2.0, not checked online"));
        Assert.That(Doctor.InventoryLines(Inventory(new([new(AcmeQuery, Now, [new("GHSA-1", null, null)])])), Now),
            Does.Contain("  npm: acme-cli 1.2.0, known vulnerabilities GHSA-1 (OSV.dev, 2026-11-26)"));
    }

    sealed class FakeSource : Dictionary<PackageQuery, IReadOnlyList<Advisory>>, IAdvisorySource
    {
        public List<PackageQuery> Asked { get; } = [];

        public Task<IReadOnlyList<Advisory>?> AdvisoriesAsync(PackageQuery package, CancellationToken cancellationToken)
        {
            Asked.Add(package);
            return Task.FromResult(TryGetValue(package, out var advisories) ? advisories : null);
        }
    }

    sealed class Probe(TrustLookups lookups) : IDoctorProbe
    {
        public bool Enrolled => true;
        public bool HasDeviceKey => true;
        public bool RecoveryKeySet => true;
        public Task<int?> BrokerStatusAsync() => Task.FromResult<int?>(401);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(true);
        public IEnumerable<DoctorFile> UserSecretsFiles() => [];
        public IEnumerable<DoctorFile> Projects() => [];
        public DoctorVault? Vault => new(2, [], []);
        public IReadOnlyList<GlobalTool> GlobalTools() => [Acme];
        public TrustLookups? TrustLookups => lookups;
    }
}
