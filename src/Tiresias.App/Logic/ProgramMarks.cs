namespace Tiresias.App.Logic;

/// <summary>The mark a program carries in the Installed and Startup lists, from its file's signature.</summary>
public enum ProgramMark
{
    /// <summary>Signed, or its signature couldn't be checked (a part of Windows, a Store app, no file).</summary>
    None,

    /// <summary>No valid signature: a caution, with Show's <i>Not signed</i>.</summary>
    Unsigned,

    /// <summary>No signature, and it looks like the user's own build on a PC that shows developer tools: information only (#148).</summary>
    BuiltByYou,
}

/// <summary>
/// The one place Installed and Startup decide a program's mark, so both lists (and a later rule,
/// such as a trusted publisher) say the same thing about the same file.
/// </summary>
public static class ProgramMarks
{
    /// <param name="valid">The signature's verdict; <c>null</c> while unchecked or when it can't be checked.</param>
    /// <param name="builtByYou">What <see cref="Tiresias.Client.OwnBuild.Looks"/> said: no signature at all, in a work tree with its project.</param>
    /// <param name="developerTools">Developer tools show (docs/developer-tools.md); without them an own build is unsigned like any other.</param>
    public static ProgramMark Of(bool? valid, bool builtByYou, bool developerTools) => valid switch
    {
        false when builtByYou && developerTools => ProgramMark.BuiltByYou,
        false => ProgramMark.Unsigned,
        _ => ProgramMark.None,
    };
}
