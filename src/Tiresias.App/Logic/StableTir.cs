namespace Tiresias.App.Logic;

/// <summary>
/// Where <c>tir</c> runs from, outside Velopack's install folder (#177). A <c>tir run</c> lasts as long
/// as its program, and a <c>tir</c> running from the install folder stops an update from applying.
/// So the app copies its version folder to <c>tir\&lt;version&gt;</c> under <paramref name="Root"/>
/// (<c>%LOCALAPPDATA%\Tiresias</c>), and PATH holds only <c>bin</c>, whose <c>tir.exe</c> is the shim
/// that runs the newest copy. A running <c>tir</c> keeps its own copy until it exits; new ones get
/// the new version.
/// </summary>
public sealed record StableTir(string Root)
{
    public string Bin => Root + @"\bin";

    public string Shim => Bin + @"\tir.exe";

    public string Pointer => Bin + @"\" + TirShim.PointerFile;

    public string Versions => Root + @"\tir";

    public string Version(string version) => Versions + @"\" + version;

    /// <summary>The real <c>tir.exe</c> of <paramref name="version"/>'s copy: what the pointer names.</summary>
    public string Tir(string version) => Version(version) + @"\tir.exe";

    /// <summary>
    /// The folders under <see cref="Versions"/> to remove: every one but <paramref name="current"/>'s,
    /// half-done copies included. The app skips one a program still runs from.
    /// </summary>
    public static IEnumerable<string> Stale(IEnumerable<string> folderNames, string current) =>
        folderNames.Where(name => !string.Equals(name, current, StringComparison.OrdinalIgnoreCase));
}
