using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Tiresias.Client;

/// <summary>
/// PowerShell modules installed for the user (#107), in <c>Documents\PowerShell\Modules</c> (PowerShell
/// 7) or <c>Documents\WindowsPowerShell\Modules</c> (Windows PowerShell 5.1). A module is code every
/// session of that shell can load, so it is judged like an extension of it.
/// </summary>
public static partial class Doctor
{
    const string PowerShellSchema = "http://schemas.microsoft.com/powershell/2004/04";

    /// <summary>
    /// A module from its folder name and, when PowerShellGet or PSResourceGet installed it, the
    /// <c>PSGetModuleInfo.xml</c> they leave beside it. Installed from the PowerShell Gallery (by its
    /// https address, not the repository's name, which the user picks) its publisher is the
    /// Gallery; copied in by hand or from another repository, unknown.
    /// </summary>
    /// <param name="folderVersion">The version folder it sits in, or <c>null</c> for a module without one.</param>
    /// <param name="updated">When its folder was made, for a module without install info.</param>
    public static InstalledExtension? PowerShellModule(ExtensionHost host, string name, string? folderVersion, string? installInfo, DateTimeOffset? updated)
    {
        if (!ModuleName().IsMatch(name))
            return null;
        var info = InstallInfo(installInfo);
        string? Text(string key) => info.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
        DateTimeOffset? When(string key) => DateTimeOffset.TryParse(Text(key), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at) ? at : null;
        var gallery = Uri.TryCreate(Text("RepositorySourceLocation"), UriKind.Absolute, out var source)
            && source.Scheme == Uri.UriSchemeHttps && source.Host.Equals("www.powershellgallery.com", StringComparison.OrdinalIgnoreCase);
        return new(host, name, Text("Version") ?? folderVersion, gallery ? "PowerShell Gallery" : null, When("UpdatedDate") ?? When("InstalledDate") ?? updated);
    }

    /// <summary>
    /// The newest of a module's version folders (<c>1.2.0</c>, <c>1.10.0</c>), compared as versions;
    /// <c>null</c> when none of them is one.
    /// </summary>
    public static string? NewestModuleVersion(IEnumerable<string> folders) =>
        folders.Where(f => Version.TryParse(f, out _)).MaxBy(Version.Parse);

    /// <summary>The top object's string and date properties of a CLIXML file; none when it isn't one.</summary>
    static Dictionary<string, string> InstallInfo(string? xml)
    {
        Dictionary<string, string> properties = new(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(xml))
            return properties;
        XDocument document;
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            document = XDocument.Load(reader);
        }
        catch (XmlException)
        {
            return properties;
        }
        XNamespace ns = PowerShellSchema;
        var top = document.Root?.Element(ns + "Obj")?.Element(ns + "MS");
        foreach (var property in top?.Elements() ?? [])
            if (property.Name == ns + "S" || property.Name == ns + "DT")
                if (property.Attribute("N")?.Value is { } key)
                    properties.TryAdd(key, property.Value);
        return properties;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]*$")]
    private static partial Regex ModuleName();
}
