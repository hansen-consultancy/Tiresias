namespace Tiresias.Client;

public static partial class Doctor
{
    /// <summary>
    /// Whether <paramref name="value"/> may go between double quotes in a command the user copies
    /// into cmd, PowerShell or bash: letters, digits and <c>/:._@+-</c> only, as the files it comes
    /// from are anyone's to write. A <paramref name="path"/> may also hold spaces and backslashes,
    /// though not a backslash last, where it would escape bash's closing quote.
    /// </summary>
    internal static bool Pastable(string value, bool path = false) =>
        value.Length > 0 && !value.EndsWith('\\', StringComparison.Ordinal)
        && value.All(c => char.IsAsciiLetterOrDigit(c) || "/:._@+-".Contains(c, StringComparison.Ordinal) || (path && c is '\\' or ' '));
}
