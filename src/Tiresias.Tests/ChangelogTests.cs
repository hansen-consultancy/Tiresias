using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Tiresias.Tests;

/// <summary>
/// CHANGELOG.md is where the release notes come from (.github/scripts/release-notes.sh), so the
/// version the build packs must have its section before it can be tagged.
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
    public void The_version_the_build_packs_has_notes()
    {
        var props = XDocument.Load(Path.Combine(RepoRoot(), "Directory.Build.props")).Descendants();
        var version = $"{props.Single(e => e.Name.LocalName == "VersionPrefix").Value}-{props.Single(e => e.Name.LocalName == "VersionSuffix").Value}";

        var section = Regex.Match(Changelog, $@"^## \[{Regex.Escape(version)}\][^\n]*\n(?<body>.*?)(?=^## \[|\z)", RegexOptions.Multiline | RegexOptions.Singleline);

        Assert.That(section.Success, Is.True, $"CHANGELOG.md has no '## [{version}]' section.");
        Assert.That(Regex.IsMatch(section.Groups["body"].Value, "^- ", RegexOptions.Multiline), Is.True, $"'## [{version}]' lists no change.");
    }
}
