using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>What the Installed page's details panel says beyond the list: who signed it, where to look it up.</summary>
public static class InstalledDetails
{
    /// <summary>
    /// The string key (and its argument) for a program file's signature. A name from a signature that
    /// doesn't verify is shown only as a claim, since anyone can write any name into one.
    /// </summary>
    public static (string Key, string? Argument) Signer(bool? valid, string? signer) => (valid, signer) switch
    {
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
    /// A web search for the program by name and version; nothing else about the PC goes in it.
    /// DuckDuckGo, because it doesn't tie the search to an account.
    /// </summary>
    public static Uri SearchOnline(string name, string? version) =>
        new("https://duckduckgo.com/?q=" + Uri.EscapeDataString(string.IsNullOrWhiteSpace(version) ? $"\"{name}\"" : $"\"{name}\" {version}"));
}
