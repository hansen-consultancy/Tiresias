using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class TirShimTests
{
    const string Real = @"C:\Users\u\AppData\Local\Tiresias\tir\0.6.0\tir.exe";

    [TestCase(@"tir run --only db -- app.exe ""a b""", @" run --only db -- app.exe ""a b""")]
    [TestCase(@"""C:\Users\u\AppData\Local\Tiresias\bin\tir.exe"" status", " status")]
    [TestCase("tir.exe\tstatus", "\tstatus")]
    [TestCase("tir", "")]
    [TestCase(@"""tir""", "")]
    public void Swaps_the_program_and_keeps_the_arguments_byte_for_byte(string original, string arguments)
    {
        Assert.That(TirShim.CommandLine(Real, original), Is.EqualTo($"\"{Real}\"{arguments}"));
    }

    [Test]
    public void A_program_with_a_space_ends_at_its_closing_quote()
    {
        Assert.That(TirShim.CommandLine(Real, @"""C:\My Tools\tir.exe"" x"), Is.EqualTo($"\"{Real}\" x"));
    }
}
