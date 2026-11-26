namespace Tiresias.App.Logic;

/// <summary>
/// What the <c>tir.exe</c> on PATH (the shim, <c>src/Tiresias.TirShim</c>) and the app agree on: the
/// shim reads the full path of the real <c>tir.exe</c> from <see cref="PointerFile"/> beside itself
/// and starts it with its own arguments, unchanged (#177).
/// </summary>
public static class TirShim
{
    public const string PointerFile = "tir.path";

    /// <summary>The name the shim ships under in the install folder, beside the real <c>tir.exe</c>.</summary>
    public const string PackagedName = "tir-shim.exe";

    /// <summary>
    /// <paramref name="original"/> (the shim's own command line) with its program swapped for
    /// <paramref name="program"/>, every argument after it kept byte for byte. The program token ends
    /// as Windows parses it: at the closing quote when quoted, otherwise at the first space or tab.
    /// </summary>
    public static string CommandLine(string program, string original)
    {
        int rest;
        if (original.Length > 0 && original[0] == '"')
        {
            var close = original.IndexOf("\"", 1, StringComparison.Ordinal);
            rest = close < 0 ? original.Length : close + 1;
        }
        else
        {
            rest = original.IndexOfAny([' ', '\t']);
            if (rest < 0)
                rest = original.Length;
        }
        return $"\"{program}\"{original[rest..]}";
    }
}
