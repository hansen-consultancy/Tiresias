using NUnit.Framework;
using Tiresias.Client;

namespace Tiresias.Tests;

public class ExtensionHostTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);
    static readonly ExtensionHost Edge = new("Edge", "msedge.exe", null, "edge://extensions");
    static readonly ExtensionHost Firefox = new("Firefox", "firefox.exe", null, "about:addons");
    static readonly ExtensionHost VisualStudio = new("Visual Studio", "devenv.exe", null, "Extensions, Manage Extensions");
    const string Id = "abcdefghijklmnopabcdefghijklmnop";

    static InstalledExtension? Chromium(string manifest, Func<string, string?>? messages = null, string id = Id) =>
        Doctor.ChromiumExtension(Edge, id, manifest, messages ?? (_ => null), Now);

    [Test]
    public void A_store_extension_names_its_store_as_publisher()
    {
        var extension = Chromium("""{ "name": "Acme Helper", "version": "1.2.0", "update_url": "https://clients2.google.com/service/update2/crx" }""");

        Assert.That(extension, Is.EqualTo(new InstalledExtension(Edge, Id, "1.2.0", "Chrome Web Store", Now, Name: "Acme Helper")));
        Assert.That(Chromium("""{ "name": "X", "update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx" }""")?.Publisher, Is.EqualTo("Edge Add-ons"));
        Assert.That(Chromium("""{ "name": "X", "update_url": "https://extension-updates.opera.com/api/omaha/update/" }""")?.Publisher, Is.EqualTo("Opera add-ons"));
    }

    [TestCase("""{ "name": "X" }""")]
    [TestCase("""{ "name": "X", "update_url": "https://updates.example.com/crx" }""")]
    [TestCase("""{ "name": "X", "update_url": "http://clients2.google.com/service/update2/crx" }""")]
    public void One_from_anywhere_else_has_an_unknown_publisher(string manifest) =>
        Assert.That(Chromium(manifest)?.Publisher, Is.Null);

    [Test]
    public void A_localized_name_comes_from_the_default_locale_ignoring_case()
    {
        string? asked = null;
        var extension = Chromium("""{ "name": "__MSG_extName__", "default_locale": "en_US" }""",
            locale => { asked = locale; return """{ "EXTNAME": { "message": "Acme Helper" } }"""; });

        Assert.That(asked, Is.EqualTo("en_US"));
        Assert.That(extension?.Name, Is.EqualTo("Acme Helper"));
    }

    [Test]
    public void A_locale_that_isnt_a_folder_name_is_never_read()
    {
        var read = false;
        var extension = Chromium("""{ "name": "__MSG_n__", "default_locale": "..\\..\\x" }""", _ => { read = true; return null; });

        Assert.That(read, Is.False);
        Assert.That(extension?.Name, Is.Null);
        Assert.That(extension?.Label, Is.EqualTo(Id));
    }

    [Test]
    public void Themes_bad_ids_and_damaged_manifests_are_left_out()
    {
        Assert.That(Chromium("""{ "name": "Dark", "theme": { "colors": {} } }"""), Is.Null);
        Assert.That(Chromium("""{ "name": "X" }""", id: "not-an-id"), Is.Null);
        Assert.That(Chromium("not json"), Is.Null);
        Assert.That(Chromium("[]"), Is.Null);
    }

    [Test]
    public void Firefox_lists_what_the_user_installed_and_has_on()
    {
        const string json = """
            { "addons": [
              { "id": "acme@example.com", "type": "extension", "location": "app-profile", "version": "2.0", "signedState": 2,
                "updateDate": 1763200000000, "defaultLocale": { "name": "Acme" } },
              { "id": "self@example.com", "type": "extension", "location": "app-profile", "version": "0.1", "signedState": 0 },
              { "id": "off@example.com", "type": "extension", "location": "app-profile", "userDisabled": true },
              { "id": "builtin@mozilla.org", "type": "extension", "location": "app-builtin" },
              { "id": "dict@example.com", "type": "dictionary", "location": "app-profile" }
            ] }
            """;

        Assert.That(Doctor.FirefoxExtensions(Firefox, json), Is.EqualTo(new InstalledExtension[]
        {
            new(Firefox, "acme@example.com", "2.0", "Firefox Add-ons", DateTimeOffset.FromUnixTimeMilliseconds(1763200000000), Name: "Acme"),
            new(Firefox, "self@example.com", "0.1", null, null),
        }));
    }

    [TestCase(null)]
    [TestCase("{}")]
    [TestCase("""{ "addons": 3 }""")]
    public void A_missing_or_odd_Firefox_file_lists_nothing(string? json) =>
        Assert.That(Doctor.FirefoxExtensions(Firefox, json), Is.Empty);

    [Test]
    public void Visual_Studio_reads_the_manifest_identity()
    {
        const string manifest = """
            <?xml version="1.0" encoding="utf-8"?>
            <PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
              <Metadata>
                <Identity Id="Acme.Tools.1234" Version="3.1" Language="en-US" Publisher="Acme" />
                <DisplayName>Acme Tools</DisplayName>
              </Metadata>
            </PackageManifest>
            """;

        Assert.That(Doctor.VisualStudioExtension(VisualStudio, manifest, Now),
            Is.EqualTo(new InstalledExtension(VisualStudio, "Acme.Tools.1234", "3.1", "Acme", Now, Name: "Acme Tools")));
    }

    [TestCase(null)]
    [TestCase("not xml")]
    [TestCase("""<PackageManifest xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata /></PackageManifest>""")]
    [TestCase("""<!DOCTYPE x [<!ENTITY e "x">]><PackageManifest xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata><Identity Id="&e;" /></Metadata></PackageManifest>""")]
    public void A_damaged_or_DTD_carrying_manifest_is_left_out(string? manifest) =>
        Assert.That(Doctor.VisualStudioExtension(VisualStudio, manifest, Now), Is.Null);

    [Test]
    public void A_browser_extension_in_a_browser_that_used_a_credential_says_where_to_remove_it()
    {
        var extension = new InstalledExtension(Edge, Id, "1.0", null, Now, Name: "Acme Helper");

        var finding = Doctor.AttackSurface([extension], [], [new(@"C:\Program Files\Edge\msedge.exe", "github", Now.AddDays(-1))], [], Now).Single();

        Assert.That(finding.Name, Is.EqualTo("Acme Helper in Edge (unknown publisher)"));
        Assert.That(finding.Fix, Is.EqualTo(new RemoveExtensionByHand(Edge, "Acme Helper")));
        Assert.That(finding.Fix!.Instruction, Is.EqualTo("remove Acme Helper in Edge, edge://extensions"));
        Assert.That(finding.Signer, Is.Null);
    }
}
