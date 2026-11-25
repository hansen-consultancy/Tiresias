using NUnit.Framework;
using Tiresias.Client;

namespace Tiresias.Tests;

public class PluginHostTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 25, 10, 0, 0, TimeSpan.Zero);
    static readonly ExtensionHost Rider = new("Rider", "rider64.exe", null, "Settings, Plugins, Installed");
    static readonly ExtensionHost NotepadPlusPlus = new("Notepad++", "notepad++.exe", null, "Plugins, Plugins Admin, Installed");

    [TestCase("Rider2025.2", "Rider", "rider64.exe", "2025.2")]
    [TestCase("IntelliJIdea2024.3", "IntelliJ IDEA", "idea64.exe", "2024.3")]
    [TestCase("IdeaIC2024.3", "IntelliJ IDEA Community", "idea64.exe", "2024.3")]
    [TestCase("PyCharmCE2025.1.2", "PyCharm Community", "pycharm64.exe", "2025.1.2")]
    public void A_settings_folder_names_its_ide_and_version(string folder, string name, string executable, string version)
    {
        var ide = Doctor.JetBrainsIde(folder);

        Assert.That(ide?.Host, Is.EqualTo(new ExtensionHost(name, executable, null, "Settings, Plugins, Installed")));
        Assert.That(ide?.Version, Is.EqualTo(Version.Parse(version)));
    }

    [TestCase("Toolbox")]
    [TestCase("consentOptions")]
    [TestCase("Rider2025.2-backup")]
    [TestCase("Fleet2025.1")]
    public void Any_other_folder_is_no_ide(string folder) =>
        Assert.That(Doctor.JetBrainsIde(folder), Is.Null);

    [Test]
    public void A_plugin_xml_gives_id_name_version_and_vendor()
    {
        var plugin = Doctor.JetBrainsPlugin(Rider, """
            <idea-plugin>
              <id>com.example.helper</id>
              <name>Acme Helper</name>
              <version>1.4.0</version>
              <vendor email="alice@example.com" url="https://example.com">Acme</vendor>
            </idea-plugin>
            """, Now);

        Assert.That(plugin, Is.EqualTo(new InstalledExtension(Rider, "com.example.helper", "1.4.0", "Acme", Now, Name: "Acme Helper")));
    }

    [Test]
    public void Without_an_id_the_name_is_the_id()
    {
        var plugin = Doctor.JetBrainsPlugin(Rider, "<idea-plugin><name>Acme Helper</name></idea-plugin>", Now);

        Assert.That(plugin, Is.EqualTo(new InstalledExtension(Rider, "Acme Helper", null, null, Now)));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("not xml")]
    [TestCase("<idea-plugin><version>1.0</version></idea-plugin>")]
    [TestCase("<plugin><id>x</id></plugin>")]
    [TestCase("<!DOCTYPE idea-plugin [<!ENTITY x \"y\">]><idea-plugin><id>&x;</id></idea-plugin>")]
    public void Anything_else_is_no_plugin(string? xml) =>
        Assert.That(Doctor.JetBrainsPlugin(Rider, xml, Now), Is.Null);

    [Test]
    public void A_signed_notepad_plus_plus_plugin_names_its_signer()
    {
        var plugin = Doctor.NotepadPlusPlusPlugin(NotepadPlusPlus, "AcmeTools", " 2.1.0 ", "Acme", Now);

        Assert.That(plugin, Is.EqualTo(new InstalledExtension(NotepadPlusPlus, "AcmeTools", "2.1.0", "Acme", Now)));
        Assert.That(Doctor.NotepadPlusPlusPlugin(NotepadPlusPlus, "AcmeTools", null, null, Now)?.Publisher, Is.Null);
    }

    [TestCase("Config")]
    [TestCase("disabled")]
    [TestCase("..")]
    [TestCase("")]
    public void Notepad_plus_plus_own_folders_are_no_plugin(string folder) =>
        Assert.That(Doctor.NotepadPlusPlusPlugin(NotepadPlusPlus, folder, "1.0", null, Now), Is.Null);

    [Test]
    public void An_unknown_plugin_in_an_editor_that_reached_a_credential_says_where_to_remove_it()
    {
        var plugin = Doctor.NotepadPlusPlusPlugin(NotepadPlusPlus, "AcmeTools", "2.1.0", null, Now)!;

        var finding = Doctor.AttackSurface([plugin], [], [new(@"C:\Program Files\Notepad++\notepad++.exe", "github", Now.AddDays(-1))], [], Now).Single();

        Assert.That(finding.Name, Is.EqualTo("AcmeTools in Notepad++ (unknown publisher)"));
        Assert.That(finding.Fix!.Instruction, Is.EqualTo("remove AcmeTools in Notepad++, Plugins, Plugins Admin, Installed"));
    }
}
