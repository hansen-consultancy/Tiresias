using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Tiresias.Client;

/// <summary>
/// Extension hosts beyond VS Code and its forks (#107): Chromium browsers (Opera included), Firefox and Visual Studio.
/// Each reads the host's own metadata for an extension, never its code. None has a command to
/// remove one, so their findings say where to do it by hand.
/// </summary>
public static partial class Doctor
{
    /// <summary>
    /// A Chromium browser extension from its <c>manifest.json</c>, as installed in a profile's
    /// <c>Extensions\&lt;id&gt;\&lt;version&gt;</c> folder. The publisher is the store it updates from
    /// (Chrome Web Store, Edge Add-ons, Opera add-ons), else unknown: installed from elsewhere. A theme holds no code
    /// and is left out, as is anything that isn't a 32-letter extension id.
    /// </summary>
    /// <param name="messages">The <c>messages.json</c> of a locale, by its folder name, for a name given as <c>__MSG_key__</c>; <c>null</c> when missing.</param>
    /// <param name="updated">When this version was put on disk: its folder's creation time.</param>
    public static InstalledExtension? ChromiumExtension(ExtensionHost host, string id, string? manifest, Func<string, string?> messages, DateTimeOffset? updated)
    {
        if (!ChromiumId().IsMatch(id))
            return null;
        return ReadObject(manifest, root =>
        {
            if (root.TryGetProperty("theme", out _))
                return null;
            var name = Text(root, "name");
            if (name is not null && LocalizedName().Match(name) is { Success: true } localized)
                name = Text(root, "default_locale") is { } locale && SafeFolder().IsMatch(locale)
                    ? Message(messages(locale), localized.Groups[1].Value) : null;
            var store = Text(root, "update_url") is { } url && Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
                ? uri.Host.ToLowerInvariant() switch
                {
                    "clients2.google.com" => "Chrome Web Store",
                    "edge.microsoft.com" => "Edge Add-ons",
                    "extension-updates.opera.com" => "Opera add-ons",
                    _ => null,
                }
                : null;
            return new InstalledExtension(host, id, Text(root, "version"), store, updated, Name: string.IsNullOrWhiteSpace(name) ? null : name.Trim());
        });
    }

    /// <summary>
    /// The unpacked extensions in a Chromium profile's <c>Secure Preferences</c> or <c>Preferences</c>:
    /// those loaded from a folder in developer mode (location 4) or from the command line (8). They
    /// live outside the <c>Extensions</c> folder, so this is the only place that names them. Nothing
    /// vouches for one, so its publisher is always unknown, whatever its manifest claims. The manifest
    /// recorded there is used, else the folder's own; a folder that isn't a local path (a share,
    /// which reading would sign in to) is never read.
    /// </summary>
    /// <param name="read">Reads a file by its full path; <c>null</c> when missing.</param>
    public static IEnumerable<InstalledExtension> UnpackedChromiumExtensions(ExtensionHost host, string? preferences, Func<string, string?> read) =>
        ReadObject(preferences, root =>
        {
            if (!root.TryGetProperty("extensions", out var extensions) || extensions.ValueKind != JsonValueKind.Object)
                return [];
            List<InstalledExtension> found = [];
            foreach (var settings in extensions.EnumerateObject().Where(p => p.Name is "settings" or "opsettings" && p.Value.ValueKind == JsonValueKind.Object))
                foreach (var (id, entry) in settings.Value.EnumerateObject().Select(p => (p.Name, p.Value)))
                {
                    if (entry.ValueKind != JsonValueKind.Object || !entry.TryGetProperty("location", out var location)
                        || !Number(location, out var where) || where is not (4 or 8))
                        continue;
                    var folder = Text(entry, "path") is { } path && Path.IsPathFullyQualified(path) && !path.StartsWith(@"\\", StringComparison.Ordinal) ? path : null;
                    var manifest = entry.TryGetProperty("manifest", out var recorded) && recorded.ValueKind == JsonValueKind.Object
                        ? recorded.GetRawText() : folder is null ? null : read(Path.Combine(folder, "manifest.json"));
                    if (ChromiumExtension(host, id, manifest, locale => folder is null ? null : read(Path.Combine(folder, "_locales", locale, "messages.json")),
                            ChromiumTime(Text(entry, "last_update_time") ?? Text(entry, "first_install_time"))) is { } extension)
                        found.Add(extension with { Publisher = null });
                }
            return (IReadOnlyList<InstalledExtension>)found;
        }) ?? [];

    /// <summary>A whole number; <c>false</c> for any other value, which <c>TryGetInt64</c> would throw on.</summary>
    static bool Number(JsonElement element, out long value)
    {
        value = 0;
        return element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out value);
    }

    /// <summary>Chromium's time stamps: microseconds since 1601 (a Windows file time), as text.</summary>
    static DateTimeOffset? ChromiumTime(string? microseconds) =>
        long.TryParse(microseconds, out var value) && value > 0 && value < DateTimeOffset.MaxValue.ToFileTime() / 10
            ? DateTimeOffset.FromFileTime(value * 10).ToUniversalTime() : null;

    /// <summary>
    /// The extensions in a Firefox profile's <c>extensions.json</c> that the user installed and has on
    /// (<c>app-profile</c>, not disabled): built-in and system add-ons are Firefox's own. One Mozilla
    /// signed (<c>signedState</c> 2 or more) is published through Firefox Add-ons, else unknown.
    /// </summary>
    public static IEnumerable<InstalledExtension> FirefoxExtensions(ExtensionHost host, string? json) =>
        ReadObject(json, root =>
        {
            if (!root.TryGetProperty("addons", out var addons) || addons.ValueKind != JsonValueKind.Array)
                return [];
            List<InstalledExtension> found = [];
            foreach (var addon in addons.EnumerateArray())
            {
                if (addon.ValueKind != JsonValueKind.Object || Text(addon, "type") != "extension" || Text(addon, "location") != "app-profile"
                    || addon.TryGetProperty("userDisabled", out var disabled) && disabled.ValueKind == JsonValueKind.True
                    || Text(addon, "id") is not { Length: > 0 } id)
                    continue;
                var signed = addon.TryGetProperty("signedState", out var state) && Number(state, out var value) && value >= 2;
                DateTimeOffset? updated = addon.TryGetProperty("updateDate", out var stamp) && Number(stamp, out var ms)
                    && ms >= 0 && ms <= DateTimeOffset.MaxValue.ToUnixTimeMilliseconds() ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null;
                var name = addon.TryGetProperty("defaultLocale", out var locale) && locale.ValueKind == JsonValueKind.Object ? Text(locale, "name") : null;
                found.Add(new(host, id, Text(addon, "version"), signed ? "Firefox Add-ons" : null, updated, Name: string.IsNullOrWhiteSpace(name) ? null : name));
            }
            return (IReadOnlyList<InstalledExtension>)found;
        }) ?? [];

    const string VsixSchema = "http://schemas.microsoft.com/developer/vsx-schema/2011";

    /// <summary>
    /// A Visual Studio extension from its <c>extension.vsixmanifest</c> (the 2011 schema, Visual
    /// Studio 2017 and later), installed for the user. Its publisher is the one the manifest names:
    /// the marketplace's verification isn't on disk, so it can't be trusted per publisher.
    /// </summary>
    /// <param name="updated">When it was put on disk: the manifest's write time.</param>
    public static InstalledExtension? VisualStudioExtension(ExtensionHost host, string? manifest, DateTimeOffset? updated)
    {
        if (string.IsNullOrWhiteSpace(manifest))
            return null;
        XDocument document;
        try
        {
            using var reader = XmlReader.Create(new StringReader(manifest), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            document = XDocument.Load(reader);
        }
        catch (XmlException)
        {
            return null;
        }
        XNamespace ns = VsixSchema;
        var metadata = document.Root?.Element(ns + "Metadata");
        var identity = metadata?.Element(ns + "Identity");
        if (identity?.Attribute("Id")?.Value is not { Length: > 0 } id)
            return null;
        var publisher = identity.Attribute("Publisher")?.Value;
        var name = metadata!.Element(ns + "DisplayName")?.Value;
        return new(host, id, identity.Attribute("Version")?.Value, string.IsNullOrWhiteSpace(publisher) ? null : publisher.Trim(), updated,
            Name: string.IsNullOrWhiteSpace(name) ? null : name.Trim());
    }

    static T? ReadObject<T>(string? json, Func<JsonElement, T?> read) where T : class
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            return document.RootElement.ValueKind == JsonValueKind.Object ? read(document.RootElement) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>A message's text by key, which Chromium matches ignoring case.</summary>
    static string? Message(string? messages, string key) =>
        ReadObject(messages, root => root.EnumerateObject().FirstOrDefault(p => string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase)) is
            { Value.ValueKind: JsonValueKind.Object } entry ? Text(entry.Value, "message") : null);

    [GeneratedRegex("^[a-p]{32}$")]
    private static partial Regex ChromiumId();

    [GeneratedRegex("^__MSG_([A-Za-z0-9_@]+)__$")]
    private static partial Regex LocalizedName();

    [GeneratedRegex("^[A-Za-z]{2,3}(_[A-Za-z0-9]{2,8})*$")]
    private static partial Regex SafeFolder();
}
