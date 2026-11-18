using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class UserPathTests
{
    const string Tir = @"C:\Users\u\AppData\Local\Tiresias\current";

    [Test]
    public void Appends_the_folder_and_keeps_every_other_entry()
    {
        Assert.That(UserPath.With(@"%USERPROFILE%\bin;C:\tools", Tir), Is.EqualTo($@"%USERPROFILE%\bin;C:\tools;{Tir}"));
    }

    [Test]
    public void An_empty_or_missing_path_gets_just_the_folder()
    {
        Assert.That(UserPath.With(null, Tir), Is.EqualTo(Tir));
        Assert.That(UserPath.With("", Tir), Is.EqualTo(Tir));
    }

    [TestCase(Tir)]
    [TestCase(Tir + @"\")]
    [TestCase(@"c:\users\U\appdata\local\tiresias\CURRENT")]
    public void Already_there_in_any_spelling_changes_nothing(string present)
    {
        Assert.That(UserPath.With($@"C:\tools;{present}", Tir), Is.Null);
    }

    [Test]
    public void Remove_takes_out_every_copy_and_nothing_else()
    {
        Assert.That(UserPath.Without($@"{Tir};C:\tools;{Tir}\", Tir), Is.EqualTo(@"C:\tools"));
        Assert.That(UserPath.Without(@"C:\tools", Tir), Is.Null);
    }

    [Test]
    public void Tir_is_found_beside_the_app_or_in_a_cli_folder_next_to_it()
    {
        Assert.That(UserPath.TirFolder(@"C:\T\app\", p => p == @"C:\T\app\tir.exe"), Is.EqualTo(@"C:\T\app"));
        Assert.That(UserPath.TirFolder(@"C:\T\app\", p => p == @"C:\T\cli\tir.exe"), Is.EqualTo(@"C:\T\cli"));
        Assert.That(UserPath.TirFolder(@"C:\T\app\", _ => false), Is.Null);
    }
}
