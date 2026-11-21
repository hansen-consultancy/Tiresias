using Tiresias.AdminTier;
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

    [Test]
    public void Held_by_the_admin_tier_only_the_kinds_show_and_nothing_more_is_placed()
    {
        var card = DecoyCard.Of(null, new AdminDecoysStatus(true, true, [DecoyKind.PasswordsFile, DecoyKind.Variables], 1));

        Assert.That(card.Placed, Is.Empty);
        Assert.That(card.Held, Is.EqualTo(new[] { DecoyKind.PasswordsFile, DecoyKind.Variables }));
        Assert.That(card.Placeable, Is.Empty);
        Assert.That(card.Removable, Is.True);
    }

    [Test]
    public void Local_placements_and_the_services_confirmed_kinds_are_reported_separately()
    {
        var card = DecoyCard.Of(DecoySet.Mint(_ => true).With(new(DecoyKind.Variables, "user environment", Now)),
            new AdminDecoysStatus(true, true, [DecoyKind.PasswordsFile], 1));

        Assert.That(card.Held, Is.EqualTo(new[] { DecoyKind.PasswordsFile }));
        Assert.That(card.Placed.Single().Kind, Is.EqualTo(DecoyKind.Variables));
    }

    [Test]
    public void Nothing_held_and_nothing_placed_is_nothing_to_remove() =>
        Assert.That(DecoyCard.Of(null, new AdminDecoysStatus(false, false, [], 0)).Removable, Is.False);

    [Test]
    public void The_card_distinguishes_verification_from_a_running_listener()
    {
        var pending = DecoyCard.Of(null, new AdminDecoysStatus(true, false, [DecoyKind.Variables], 0));
        Assert.That(pending.Listening, Is.False);
        Assert.That(pending.Held, Is.EqualTo(new[] { DecoyKind.Variables }));
        var legacy = DecoyCard.Of(null, new AdminDecoysStatus(false, false, [], 0, NeedsVerification: true));
        Assert.That(legacy.Held, Is.Empty);
        Assert.That(legacy.Placeable, Has.Count.EqualTo(3));
        Assert.That(legacy.CanEnroll, Is.True);
    }
}
