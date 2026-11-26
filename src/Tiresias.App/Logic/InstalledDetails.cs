using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>What the Installed page's details panel says beyond the list: who signed it, where to look it up.</summary>
public static class InstalledDetails
{
    /// <summary>
    /// The string key (and its argument) for a program file's signature. A name from a signature that
    /// doesn't verify is shown only as a claim, since anyone can write any name into one.
    /// </summary>
    /// <param name="mark">The program's mark: an own build says so.</param>
    public static (string Key, string? Argument) Signer(bool? valid, string? signer, ProgramMark mark = ProgramMark.None) => (valid, signer) switch
    {
        (false, null) when mark == ProgramMark.BuiltByYou => ("Program_NotSignedBuiltByYou", null),
        (null, _) => ("Installed_SignerUnknown", null),
        (true, { Length: > 0 }) => ("Installed_SignedBy", signer),
        (true, _) => ("Installed_SignedNoName", null),
        (false, { Length: > 0 }) => ("Installed_SignedInvalid", signer),
        (false, _) => ("Installed_NotSigned", null),
    };

    /// <summary>
    /// The string keys for the panel's trust line and its button (each with the publisher's name):
    /// only a valid signature's publisher can be trusted, so a claimed name never gets a button.
    /// </summary>
    public static (string Key, string? Argument, string? Button) Trust(Publisher? publisher, Dismissals dismissals) => publisher switch
    {
        null => ("Installed_TrustNone", null, null),
        _ when dismissals.Trusts(publisher) => ("Installed_Trusted", publisher.Name, "Finding_StopTrustingName"),
        _ => ("Installed_NotTrusted", null, "Installed_TrustButton"),
    };

    /// <summary>
    /// The string key and arguments for what the online lookups said about a global tool
    /// (docs/attack-surface.md#trust), shown beside the offline signer.
    /// </summary>
    /// <param name="lookups">The saved answers; <c>null</c> while lookups are off.</param>
    public static (string Key, string[] Arguments) Online(GlobalTool tool, TrustLookups? lookups) =>
        lookups is null ? ("Installed_OnlineOff", [])
        : PackageQuery.Of(tool) is not { } package ? ("Installed_OnlineCantCheck", [])
        : lookups.For(package) switch
        {
            null => ("Installed_OnlineNotYet", []),
            { Advisories.Count: 0, At: var at } => ("Installed_OnlineClean", [Doctor.OsvSource, Date(at)]),
            { Advisories: var advisories, At: var at } => ("Installed_OnlineVulnerable",
                [Doctor.OsvSource, Date(at), string.Join(", ", advisories.Select(a => a.Id))]),
        };

    static string Date(DateTimeOffset at) => at.ToLocalTime().ToString("d", System.Globalization.CultureInfo.CurrentCulture);

    /// <summary>
    /// A web search for the program by name and version; nothing else about the PC goes in it.
    /// DuckDuckGo, because it doesn't tie the search to an account.
    /// </summary>
    public static Uri SearchOnline(string name, string? version) =>
        new("https://duckduckgo.com/?q=" + Uri.EscapeDataString(string.IsNullOrWhiteSpace(version) ? $"\"{name}\"" : $"\"{name}\" {version}"));
}
