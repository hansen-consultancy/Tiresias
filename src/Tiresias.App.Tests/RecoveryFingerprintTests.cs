using NUnit.Framework;
using Tiresias.App.Views;
using Tiresias.Client;

namespace Tiresias.App.Tests;

public class RecoveryFingerprintTests
{
    [Test]
    public void The_restore_preview_tracks_the_complete_typed_paper_and_clears_on_edit()
    {
        var model = new RecoveryViewModel();
        byte[] paper = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var first = PaperKey.RecipientFingerprint(paper);
        var typed = PaperKey.Format(paper);
        model.TypedKey = typed;
        Assert.That(model.Fingerprint, Does.Contain(first).And.Not.Contain(typed));

        model.TypedKey = typed[..^1];
        Assert.That(model.Fingerprint, Is.Empty);
        paper[12] ^= 1;
        model.TypedKey = PaperKey.Format(paper);
        Assert.That(model.Fingerprint, Does.Contain(PaperKey.RecipientFingerprint(paper)).And.Not.Contain(first));
    }
}
