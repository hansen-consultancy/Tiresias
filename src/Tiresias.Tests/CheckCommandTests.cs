using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class CheckCommandTests
{
    [TestCase("this device's Windows Hello key isn't in the trust chain yet, so it can't add a device or change trust: run tir trust bind-hello", "tir trust bind-hello")]
    [TestCase("not set: secrets depend on this TPM alone; run tir recovery init", "tir recovery init")]
    [TestCase("not installed: run tir solo service install again", "tir solo service install")]
    [TestCase("no broker: run tir solo init.", "tir solo init")]
    [TestCase("locked (run tir unlock), then start the app again.", "tir unlock")]
    public void The_command_after_run_is_offered(string detail, string command) =>
        Assert.That(CheckCommand.Of(detail), Is.EqualTo(command));

    [TestCase("enrolled")]
    [TestCase("not running: placeholders work only against the broker directly")]
    [TestCase("run the installer")]
    public void A_detail_without_a_tir_command_offers_none(string detail) =>
        Assert.That(CheckCommand.Of(detail), Is.Null);
}
