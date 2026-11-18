using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class BuildInfoTests
{
    [Test]
    public void An_installed_copy_shows_its_version_only()
    {
        var build = BuildInfo.From("0.1.0-preview.4+5f91cdfe77756771e61d81a1f628f6455d320b40", installed: true, @"C:\Users\u\AppData\Local\TiresiasApp\current\");

        Assert.That(build.Development, Is.False);
        Assert.That(build.Label, Is.EqualTo(new Phrase("Build_Installed", "0.1.0-preview.4")).Using<Phrase>(SamePhrase));
        Assert.That(build.Folder, Is.EqualTo(@"C:\Users\u\AppData\Local\TiresiasApp\current"));
    }

    [Test]
    public void A_development_build_names_its_short_commit()
    {
        var build = BuildInfo.From("0.1.0-preview.4+5f91cdfe77756771", installed: false, @"P:\Tiresias\src\Tiresias.App\bin\Debug");

        Assert.That(build.Development, Is.True);
        Assert.That(build.Commit, Is.EqualTo("5f91cdf"));
        Assert.That(build.Label, Is.EqualTo(new Phrase("Build_DevelopmentCommit", "0.1.0-preview.4", "5f91cdf")).Using<Phrase>(SamePhrase));
    }

    [TestCase(null)]
    [TestCase("0.1.0")]
    [TestCase("0.1.0+")]
    public void A_development_build_without_a_commit_still_says_so(string? version)
    {
        var build = BuildInfo.From(version, installed: false, @"C:\build");

        Assert.That(build.Commit, Is.Null);
        Assert.That(build.Label.Key, Is.EqualTo("Build_Development"));
    }

    [TestCase(@"C:\Apps\Tiresias", true)]
    [TestCase(@"c:\apps\tiresias\", true)]
    [TestCase(@"C:\Apps\Tiresias\bin", false)]
    [TestCase(null, false)]
    public void The_same_folder_is_the_same_copy(string? other, bool same) =>
        Assert.That(BuildInfo.From("1.0.0", true, @"C:\Apps\Tiresias\").SameCopyAs(other), Is.EqualTo(same));

    static bool SamePhrase(Phrase a, Phrase b) => a.Key == b.Key && a.Args.SequenceEqual(b.Args);
}

public class ReleaseNotesTests
{
    const string Changelog = """
        # Changelog

        ## [Unreleased]

        ### Added

        - Not out yet.

        ## [0.1.0-preview.4] - 2026-11-18

        ### Fixed

        - Something.

        ## [0.1.0-preview.2] - 2026-11-17

        [Unreleased]: https://example.invalid
        """;

    [Test]
    public void Takes_one_version_up_to_the_next_heading() =>
        Assert.That(ReleaseNotes.Section(Changelog, "0.1.0-preview.4"), Is.EqualTo("### Fixed\n\n- Something."));

    [Test]
    public void A_development_build_reads_the_unreleased_section() =>
        Assert.That(ReleaseNotes.Section(Changelog, "Unreleased"), Is.EqualTo("### Added\n\n- Not out yet."));

    [Test]
    public void A_missing_version_has_no_notes() =>
        Assert.That(ReleaseNotes.Section(Changelog, "9.9.9"), Is.Null);

    [Test]
    public void A_version_is_not_mistaken_for_a_longer_one() =>
        Assert.That(ReleaseNotes.Section(Changelog, "0.1.0-preview"), Is.Null);

    [Test]
    public void Plain_text_drops_the_markdown_and_unwraps_lines() =>
        Assert.That(ReleaseNotes.Plain("""
            ### Added

            - **About Tiresias**: the version and
              where it runs from.
            - `tir status` names the app.

            A paragraph wrapped
            over two lines.
            """), Is.EqualTo(
            "Added\n\n• About Tiresias: the version and where it runs from.\n• tir status names the app.\n\nA paragraph wrapped over two lines."));
}
