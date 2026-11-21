using Tiresias.App.Logic;
using Tiresias.Decoys;

namespace Tiresias.Tests;

public class DecoyCardTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);

    [Test]
    public void With_nothing_placed_every_kind_can_be_placed()
    {
        var card = DecoyCard.Of(null);

        Assert.That(card.Placed, Is.Empty);
        Assert.That(card.Placeable, Is.EqualTo(new[] { DecoyKind.PasswordsFile, DecoyKind.Project, DecoyKind.Variables }));
    }

    [Test]
    public void A_placed_kind_is_listed_oldest_first_and_offered_no_more()
    {
        var set = DecoySet.Mint(_ => true)
            .With(new(DecoyKind.Variables, "user environment", Now))
            .With(new(DecoyKind.PasswordsFile, @"C:\Users\alice\Documents\passwords.txt", Now.AddDays(-1)));

        var card = DecoyCard.Of(set);

        Assert.That(card.Placed.Select(p => p.Kind), Is.EqualTo(new[] { DecoyKind.PasswordsFile, DecoyKind.Variables }));
        Assert.That(card.Placeable, Is.EqualTo(new[] { DecoyKind.Project }));
    }
}
