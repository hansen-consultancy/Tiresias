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
    /// A web search for the program by name and version; nothing else about the PC goes in it.
    /// DuckDuckGo, because it doesn't tie the search to an account.
    /// </summary>
    public static Uri SearchOnline(string name, string? version) =>
        new("https://duckduckgo.com/?q=" + Uri.EscapeDataString(string.IsNullOrWhiteSpace(version) ? $"\"{name}\"" : $"\"{name}\" {version}"));
}
