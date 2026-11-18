using System.Xml.Linq;

namespace Tiresias.Tests;

/// <summary>
/// Package boundaries that a build would not catch. Tiresias.Extensions.Configuration ships the
/// AddUserSecrets interceptor as an analyzer, and NuGet flows analyzers and buildTransitive props
/// to every transitive consumer: if Core depended on it, any app referencing Core (a control plane,
/// say) would have its own host builder intercepted without asking for it.
/// </summary>
public sealed class PackagingTests
{
    static string Project(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, name, name + ".csproj");
            if (File.Exists(path))
                return path;
        }
        throw new FileNotFoundException(name + ".csproj not found above the test output.");
    }

    static IEnumerable<string> References(string name) =>
        XDocument.Load(Project(name)).Descendants("ProjectReference")
            .Select(r => Path.GetFileNameWithoutExtension(r.Attribute("Include")!.Value.Replace('\\', '/')));

    /// <summary>
    /// Velopack installs to %LOCALAPPDATA%\{packId} and deletes that folder on uninstall. Sharing a
    /// name with the data folder would make uninstalling erase the vault and the device key.
    /// </summary>
    [Test]
    public void The_installer_never_installs_into_the_data_folder()
    {
        var workflow = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(Project("Tiresias.Core"))))!,
            ".github", "workflows", "app-release.yml");
        var packId = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(workflow), @"--packId\s+(\S+)").Groups[1].Value;

        Assert.That(packId, Is.Not.Empty);
        // KeyringStore.Directory is %LOCALAPPDATA%\Tiresias (Tiresias.Agent, which this project does not reference).
        Assert.That(packId, Is.Not.EqualTo("Tiresias").IgnoreCase);
    }

    [TestCase("Tiresias.Core")]
    [TestCase("Tiresias.Protocol")]
    public void Does_not_depend_on_the_configuration_package(string project) =>
        Assert.That(References(project), Has.None.EqualTo("Tiresias.Extensions.Configuration"));
}
