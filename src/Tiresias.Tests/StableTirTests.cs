using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class StableTirTests
{
    static readonly StableTir Layout = new(@"C:\Users\u\AppData\Local\Tiresias");

    [Test]
    public void Path_holds_only_bin_and_versions_live_beside_it()
    {
        Assert.That(Layout.Shim, Is.EqualTo(@"C:\Users\u\AppData\Local\Tiresias\bin\tir.exe"));
        Assert.That(Layout.Pointer, Is.EqualTo(@"C:\Users\u\AppData\Local\Tiresias\bin\tir.path"));
        Assert.That(Layout.Tir("0.6.0"), Is.EqualTo(@"C:\Users\u\AppData\Local\Tiresias\tir\0.6.0\tir.exe"));
    }

    [Test]
    public void Every_copy_but_the_running_version_is_stale_half_done_ones_too()
    {
        Assert.That(StableTir.Stale(["0.5.0", "0.6.0", "0.6.0.partial"], "0.6.0"),
            Is.EqualTo(new[] { "0.5.0", "0.6.0.partial" }));
        Assert.That(StableTir.Stale(["0.6.0-Preview.1"], "0.6.0-preview.1"), Is.Empty);
    }
}
