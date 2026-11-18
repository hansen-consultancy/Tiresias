using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class SignInStartTests
{
    const string Exe = @"C:\Users\Alice Example\AppData\Local\TiresiasApp\current\Tiresias.exe";

    [Test]
    public void The_command_is_quoted_so_a_space_in_the_profile_still_starts() =>
        Assert.That(SignInStart.Command(Exe), Is.EqualTo($"\"{Exe}\""));

    [TestCase("\"" + Exe + "\"", ExpectedResult = true)]
    [TestCase(Exe, ExpectedResult = true)]
    [TestCase("\"" + @"c:\users\alice example\appdata\local\tiresiasapp\current\tiresias.exe" + "\"", ExpectedResult = true)]
    [TestCase(@"""P:\src\Tiresias\bin\Debug\Tiresias.exe""", ExpectedResult = false)]
    [TestCase("", ExpectedResult = false)]
    [TestCase(null, ExpectedResult = false)]
    public bool Only_an_entry_for_this_copy_counts(string? command) => SignInStart.Starts(command, Exe);
}
