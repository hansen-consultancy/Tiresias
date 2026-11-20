using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class WindowPlacementTests
{
    static readonly ScreenBox Laptop = new(0, 0, 1920, 1032);

    [Test]
    public void A_window_may_take_most_of_the_work_area_height() =>
        Assert.That(WindowPlacement.MaxHeight(Laptop), Is.EqualTo(877));

    [Test]
    public void A_window_whose_list_loads_later_opens_at_a_fixed_share() =>
        Assert.That(WindowPlacement.TallHeight(Laptop), Is.EqualTo(722));

    [Test]
    public void A_window_centres_on_the_monitor() =>
        Assert.That(WindowPlacement.Centre(Laptop, 720, 500, Laptop), Is.EqualTo((600d, 266d)));

    [Test]
    public void A_dialog_centres_on_its_owner()
    {
        var owner = new ScreenBox(100, 100, 960, 700);

        Assert.That(WindowPlacement.Centre(owner, 480, 300, Laptop), Is.EqualTo((340d, 300d)));
    }

    [Test]
    public void An_owner_near_the_edge_keeps_its_dialog_on_screen()
    {
        var owner = new ScreenBox(1700, 900, 400, 200);

        Assert.That(WindowPlacement.Centre(owner, 720, 600, Laptop), Is.EqualTo((1200d, 432d)));
    }

    [Test]
    public void A_second_monitor_left_of_the_primary_uses_its_own_coordinates()
    {
        var left = new ScreenBox(-2560, 0, 2560, 1400);

        Assert.That(WindowPlacement.Centre(left, 960, 800, left), Is.EqualTo((-1760d, 300d)));
    }

    [Test]
    public void A_window_wider_than_the_work_area_keeps_its_corner_in_it()
    {
        var small = new ScreenBox(0, 0, 800, 600);

        Assert.That(WindowPlacement.Centre(small, 960, 700, small), Is.EqualTo((0d, 0d)));
    }
}
