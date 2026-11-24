using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

/// <summary>Trusting a publisher and dismissing per item (docs/attack-surface.md, Dismissals).</summary>
public class PublisherTrustTests
{
    static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    const string Folder = @"C:\Users\alice\AppData\Local\Programs\Acme";
    const string Key = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Acme";
    const string Uninstaller = $@"{Folder}\uninstall.exe";
    static readonly Publisher Acme = Publisher.Signed("CN=Acme Corp, O=Acme Corp, L=Springfield, C=US", "Acme Corp");
    static readonly Publisher Other = Publisher.Signed("CN=Other, O=Other, C=US", "Other");
    static readonly ExtensionHost Code = new("VS Code", "Code.exe", "code");
    const string CodeExe = @"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe";

    static UninstallEntry Entry(string version) => new(Key, "Acme", version, Uninstaller, true, true, null, Folder);

    static DoctorCheck Unused(string version = "2.1", Publisher? signer = null) =>
        Doctor.UnusedApplications([Entry(version)], [new($@"{Folder}\acme.exe", Now.AddDays(-200))], [], Now,
            file => file == Uninstaller ? signer : null).Single();

    static DoctorCheck Extension(string? publisherId = "6f1e-acme", string? publisher = "Acme", int updatedDaysAgo = 800) =>
        Doctor.AttackSurface([new(Code, "acme.helper", "1.0.0", publisher, Now.AddDays(-updatedDaysAgo), publisherId)], [],
            [new(CodeExe, "github", Now.AddDays(-3))], [], Now).Single();

    [Test]
    public void Trusting_a_signer_hides_its_unused_program_and_says_why()
    {
        var trusted = Dismissals.Empty.Trust(Acme, Now);

        var hidden = trusted.For(Unused(signer: Acme));

        Assert.That(hidden?.Trusted?.Key, Is.EqualTo(Acme.Key));
        Assert.That(hidden!.Reason, Is.EqualTo("you trust Acme Corp"));
    }

    [Test]
    public void Trust_is_keyed_by_the_whole_subject_so_a_same_named_signer_from_elsewhere_is_judged_on_its_own()
    {
        var lookalike = Publisher.Signed("CN=Acme Corp, O=Acme Corp, L=Elsewhere, C=XX", "Acme Corp");

        Assert.That(Dismissals.Empty.Trust(Acme, Now).For(Unused(signer: lookalike)), Is.Null);
    }

    [Test]
    public void A_program_without_a_valid_signature_cannot_be_trusted_into_hiding()
    {
        Assert.That(Unused(signer: null).Signer, Is.Null);
        Assert.That(Dismissals.Empty.Trust(Acme, Now).For(Unused(signer: null)), Is.Null);
    }

    [Test]
    public void Trust_never_hides_a_blocked_program_or_an_unsigned_one_at_log_on()
    {
        var checks = Doctor.AttackSurface([], [new("Other", StartupEntry.RunKey, @"C:\Tools\other.exe", Signed: false, "Other")], [],
            [@"C:\Tools\acme.exe"], Now).ToArray();

        Assert.That(checks, Has.Length.EqualTo(2));
        Assert.That(checks.Select(c => c.TrustHides), Is.All.False);
        Assert.That(checks.Select(Dismissals.Empty.Trust(Acme, Now).For), Is.All.Null);
    }

    [Test]
    public void A_signed_idle_log_on_entry_is_hidden_by_trust_in_its_signer()
    {
        var path = $@"{Folder}\acme.exe";
        var check = Doctor.AttackSurface([], [new("Acme", StartupEntry.RunKey, path, Signed: true, "Acme", Signer: Acme)], [], [], Now,
            [new(path, Now.AddDays(-200))]).Single();

        Assert.That(check.Kind, Is.EqualTo(Doctor.IdleStartupKind));
        Assert.That(Dismissals.Empty.Trust(Acme, Now).For(check)?.Trusted, Is.Not.Null);
    }

    [Test]
    public void An_extension_is_trusted_by_its_marketplace_publisher_id_and_one_with_no_known_publisher_never_is()
    {
        var known = Extension();
        Assert.That(known.Signer, Is.EqualTo(Publisher.Marketplace("6f1e-acme", "Acme")));
        Assert.That(Dismissals.Empty.Trust(known.Signer!, Now).For(known), Is.Not.Null);

        var unknown = Extension(publisherId: null, publisher: null);
        Assert.That(unknown.Signer, Is.Null);
        Assert.That(FindingView.Trustable([unknown]), Is.Null);
    }

    [Test]
    public void The_extension_publisher_id_is_read_from_the_hosts_metadata_and_never_for_a_vsix()
    {
        const string json = """
            [ { "identifier": { "id": "acme.helper" }, "version": "1.0.0", "metadata": { "publisherId": "6f1e-acme", "publisherDisplayName": "Acme" } },
              { "identifier": { "id": "acme.side" }, "version": "1.0.0", "metadata": { "publisherId": "6f1e-acme", "source": "vsix" } } ]
            """;

        var extensions = Doctor.Extensions(Code, json).ToArray();

        Assert.That(extensions.Select(e => e.PublisherId), Is.EqualTo(new[] { "6f1e-acme", null }));
    }

    [Test]
    public void Stopping_trust_shows_the_findings_again_and_trusting_twice_keeps_one()
    {
        var trusted = Dismissals.Empty.Trust(Acme, Now);

        Assert.That(trusted.Distrust(Acme.Key).For(Unused(signer: Acme)), Is.Null);
        Assert.That(trusted.Trust(Acme, Now.AddDays(1)).Publishers, Has.Count.EqualTo(1));
    }

    [Test]
    public void A_dismissal_survives_an_update()
    {
        var dismissed = Dismissals.Empty.Dismiss(Unused("2.1", Acme), "I use it yearly", Now);

        Assert.That(Unused("2.1", Acme).Name, Is.Not.EqualTo(Unused("3.0", Acme).Name));
        Assert.That(dismissed.For(Unused("3.0", Acme))?.Reason, Is.EqualTo("I use it yearly"));
    }

    [Test]
    public void A_changed_signer_brings_a_dismissal_back()
    {
        var dismissed = Dismissals.Empty.Dismiss(Unused(signer: Acme), "I use it yearly", Now);

        Assert.That(dismissed.For(Unused(signer: Other)), Is.Null);
        Assert.That(dismissed.For(Unused(signer: null)), Is.Null);
    }

    [Test]
    public void A_reason_the_dismissal_did_not_accept_brings_it_back_and_a_reason_gone_does_not()
    {
        var stale = Extension();
        var dismissed = Dismissals.Empty.Dismiss(stale, "finished, not abandoned", Now);
        var both = Extension(publisherId: null, publisher: null);
        Assert.That(both.Reasons, Is.EqualTo(new[] { "unknown publisher", "not updated in 2 years" }));

        Assert.That(dismissed.For(Extension(updatedDaysAgo: 3650)), Is.Not.Null);
        Assert.That(Dismissals.Empty.Dismiss(both, "I built it", Now).For(Extension(publisherId: null, publisher: null, updatedDaysAgo: 10)), Is.Not.Null);
        Assert.That(Dismissals.Empty.Dismiss(Extension(publisherId: null, publisher: null, updatedDaysAgo: 10), "I built it", Now).For(both), Is.Null);
        Assert.That(dismissed.Restore(Dismissals.KeyOf(stale)).For(stale), Is.Null);
    }

    [Test]
    public void Version_1_dismissals_still_load_and_still_hide_their_finding()
    {
        var check = Unused();
        var v1Key = Dismissals.KeyOf(check with { Item = null });
        var json = $$"""{ "v": 1, "items": [ { "key": "{{v1Key}}", "name": "Acme", "reason": "yearly", "at": "2026-01-01T00:00:00+00:00" } ] }""";

        Assert.That(Dismissals.Parse(json).For(check)?.Reason, Is.EqualTo("yearly"));
    }

    [Test]
    public void Trusted_publishers_and_item_dismissals_round_trip_in_version_2_and_a_newer_file_is_dropped()
    {
        var json = Dismissals.Empty.Trust(Acme, Now).Dismiss(Extension(), "finished", Now).ToJson();
        var loaded = Dismissals.Parse(json);

        Assert.That(json, Does.Contain("\"v\": 2"));
        Assert.That(loaded.Publishers.Single(), Is.EqualTo(new TrustedPublisher(Acme.Key, "Acme Corp", Now)));
        Assert.That(loaded.For(Extension()), Is.Not.Null);
        Assert.That(Dismissals.Parse(json.Replace("\"v\": 2", "\"v\": 3", StringComparison.Ordinal)).Publishers, Is.Empty);
    }

    [Test]
    public void Trust_hidden_findings_leave_the_badge_and_Home_lists_each_trusted_publisher_even_hiding_nothing()
    {
        var warning = Extension();
        var dismissals = Dismissals.Empty.Trust(Acme, Now).Trust(warning.Signer!, Now).Trust(Other, Now);

        var split = FindingView.Of([Unused(signer: Acme), warning], dismissals);

        Assert.That(FindingBadge.Open([warning], dismissals), Is.Empty);
        Assert.That(split.Open, Is.Empty);
        Assert.That(split.Dismissed.Select(g => (g.Publisher?.Key, g.Keys.Count)),
            Is.EqualTo(new (string?, int)[] { (Acme.Key, 1), (warning.Signer!.Key, 1), (Other.Key, 0) }));
    }

    [Test]
    public void A_row_offers_trust_only_when_all_its_findings_share_one_checked_signer()
    {
        Assert.That(FindingView.Trustable([Unused(signer: Acme), Unused("3.0", Acme)]), Is.EqualTo(Acme));
        Assert.That(FindingView.Trustable([Unused(signer: Acme), Unused(signer: Other)]), Is.Null);
        Assert.That(FindingView.Trustable([Unused(signer: Acme), Unused(signer: null)]), Is.Null);
    }

    [Test]
    public void The_Installed_panel_offers_trust_only_for_a_valid_signature()
    {
        Assert.That(InstalledDetails.Trust(null, Dismissals.Empty), Is.EqualTo(("Installed_TrustNone", (string?)null, (string?)null)));
        Assert.That(InstalledDetails.Trust(Acme, Dismissals.Empty).Button, Is.EqualTo("Installed_TrustButton"));
        Assert.That(InstalledDetails.Trust(Acme, Dismissals.Empty.Trust(Acme, Now)), Is.EqualTo(("Installed_Trusted", (string?)"Acme Corp", (string?)"Finding_StopTrustingName")));
    }

    [Test]
    public void A_demo_signer_is_named_by_its_common_name_and_keyed_by_its_whole_subject()
    {
        var signer = DemoScenario.Signer("CN=Example Tools Ltd, O=Example Tools Ltd, C=GB");

        Assert.That(signer, Is.EqualTo(new Publisher("signer:CN=Example Tools Ltd, O=Example Tools Ltd, C=GB", "Example Tools Ltd")));
    }
}
