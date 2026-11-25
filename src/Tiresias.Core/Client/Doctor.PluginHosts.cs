using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Tiresias.Client;

/// <summary>
/// Plugin hosts (#107): JetBrains IDEs and Notepad++. Like the other hosts, each plugin is read from
/// its metadata (a JetBrains <c>plugin.xml</c>, a Notepad++ plugin's file version and signature), never
/// run. Neither IDE has a command to remove one, so their findings say where to do it by hand.
/// </summary>
public static partial class Doctor
{
    const string JetBrainsPluginsPage = "Settings, Plugins, Installed";

    /// <summary>JetBrains IDEs by the name their settings folder starts with, before the version.</summary>
    static readonly Dictionary<string, (string Name, string Executable)> JetBrainsProducts = new(StringComparer.Ordinal)
    {
        ["IntelliJIdea"] = ("IntelliJ IDEA", "idea64.exe"),
        ["IdeaIC"] = ("IntelliJ IDEA Community", "idea64.exe"),
        ["Rider"] = ("Rider", "rider64.exe"),
        ["PyCharm"] = ("PyCharm", "pycharm64.exe"),
        ["PyCharmCE"] = ("PyCharm Community", "pycharm64.exe"),
        ["WebStorm"] = ("WebStorm", "webstorm64.exe"),
        ["GoLand"] = ("GoLand", "goland64.exe"),
        ["CLion"] = ("CLion", "clion64.exe"),
        ["PhpStorm"] = ("PhpStorm", "phpstorm64.exe"),
        ["DataGrip"] = ("DataGrip", "datagrip64.exe"),
        ["RubyMine"] = ("RubyMine", "rubymine64.exe"),
        ["RustRover"] = ("RustRover", "rustrover64.exe"),
        ["DataSpell"] = ("DataSpell", "dataspell64.exe"),
    };

    /// <summary>
    /// The IDE and version a settings folder under <c>%APPDATA%\JetBrains</c> belongs to, from its
    /// name (<c>Rider2025.2</c>); <c>null</c> for any other folder (Toolbox, a backup, an unknown IDE).
    /// An upgrade leaves the old version's folder behind, so only the newest of each IDE is current.
    /// </summary>
    public static (ExtensionHost Host, Version Version)? JetBrainsIde(string folder) =>
        JetBrainsFolder().Match(folder) is { Success: true } match
        && JetBrainsProducts.TryGetValue(match.Groups[1].Value, out var product)
        && Version.TryParse(match.Groups[2].Value, out var version)
            ? (new ExtensionHost(product.Name, product.Executable, null, JetBrainsPluginsPage), version)
            : null;

    /// <summary>
    /// A JetBrains plugin from its <c>META-INF/plugin.xml</c>. Its id is the <c>id</c> element, else its
    /// name, as the IDE does. The publisher is the vendor the file names: the marketplace's
    /// verification isn't on disk, so it can't be trusted per publisher.
    /// </summary>
    /// <param name="updated">When it was put on disk.</param>
    public static InstalledExtension? JetBrainsPlugin(ExtensionHost host, string? pluginXml, DateTimeOffset? updated)
    {
        if (ReadXml(pluginXml)?.Root is not { Name.LocalName: "idea-plugin" } root)
            return null;
        string? Element(string name) => root.Element(name)?.Value.Trim() is { Length: > 0 } value ? value : null;
        var name = Element("name");
        if ((Element("id") ?? name) is not { } id)
            return null;
        return new(host, id, Element("version"), Element("vendor"), updated, Name: name == id ? null : name);
    }

    /// <summary>
    /// A Notepad++ plugin: a folder in <c>plugins</c> holding a DLL of the same name. Notepad++'s own
    /// folders there (its plugin list, the disabled ones) are not plugins. The publisher is who signed
    /// the DLL, when that signature verified, else unknown: the file's own company name proves nothing.
    /// </summary>
    /// <param name="signer">The name on the DLL's signature, only when it verified.</param>
    /// <param name="updated">When the DLL was put on disk.</param>
    public static InstalledExtension? NotepadPlusPlusPlugin(ExtensionHost host, string folder, string? version, string? signer, DateTimeOffset? updated) =>
        folder is "Config" or "disabled" or "APIs" or "doc" || !PluginFolder().IsMatch(folder)
            ? null
            : new(host, folder, string.IsNullOrWhiteSpace(version) ? null : version.Trim(), string.IsNullOrWhiteSpace(signer) ? null : signer, updated);

    static XDocument? ReadXml(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
            return null;
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            return XDocument.Load(reader);
        }
        catch (XmlException)
        {
            return null;
        }
    }

    [GeneratedRegex(@"^([A-Za-z]+)(\d{4}\.\d+(?:\.\d+)?)$")]
    private static partial Regex JetBrainsFolder();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._+-]*$")]
    private static partial Regex PluginFolder();
}
