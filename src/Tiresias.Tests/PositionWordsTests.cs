using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class PositionWordsTests
{
    [Test]
    public void Every_exposure_has_its_own_word_and_meaning() =>
        Assert.That(Enum.GetValues<Exposure>().Select(e => PositionWords.Of(e).Word).Distinct().Count(), Is.EqualTo(Enum.GetValues<Exposure>().Length));

    [Test]
    public void Every_control_has_its_own_word_and_meaning() =>
        Assert.That(Enum.GetValues<Control>().Select(c => PositionWords.Of(c).Word).Distinct().Count(), Is.EqualTo(Enum.GetValues<Control>().Length));

    [Test]
    public void A_plaintext_file_reads_as_readable_and_unchecked()
    {
        Assert.That(PositionWords.Of(Position.Plaintext.Exposure), Is.EqualTo(("Position_Readable", "Position_ReadableTip")));
        Assert.That(PositionWords.Of(Position.Plaintext.Control), Is.EqualTo(("Position_Silent", "Position_SilentTip")));
    }
}
