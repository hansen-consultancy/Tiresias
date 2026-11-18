using System.Xml.Linq;

namespace Tiresias.Tests;

/// <summary>
/// CHANGELOG.md is where the release notes come from (.github/scripts/release-notes.sh, which fails
/// a tag whose version has no section). The version in Directory.Build.props is for local builds
/// only: both release workflows set Version from the tag.
/// </summary>
public class ChangelogTests
{
    static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Tiresias.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Tiresias.slnx not found above the test directory.");
    }

    static string Changelog => File.ReadAllText(Path.Combine(RepoRoot(), "CHANGELOG.md"));

    [Test]
    public void Has_an_unreleased_section_to_add_to() =>
        Assert.That(Changelog, Does.Contain("\n## [Unreleased]"));

    [Test]
    public void A_local_build_never_claims_a_released_version()
    {
        var props = XDocument.Load(Path.Combine(RepoRoot(), "Directory.Build.props")).Descendants();
        var suffix = props.Single(e => e.Name.LocalName == "VersionSuffix").Value;

        Assert.That(suffix, Is.EqualTo("dev"), "Directory.Build.props versions local builds; a release takes its version from the tag.");
        Assert.That(Changelog, Does.Not.Contain($"## [{props.Single(e => e.Name.LocalName == "VersionPrefix").Value}-dev]"));
    }
}
