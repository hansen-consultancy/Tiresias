using Tiresias.AdminTier;
using Tiresias.Decoys;

namespace Tiresias.App.Logic;

/// <summary>
/// Home's decoys card: what is placed, and which kinds can still be placed from the app (each once,
/// at its default place; another place is <c>tir decoys place</c>'s). When the admin tier holds the
/// set, only its kinds are known (<see cref="Held"/>), and nothing more is placed beside it.
/// </summary>
public sealed record DecoyCard(IReadOnlyList<PlacedDecoy> Placed, IReadOnlyList<DecoyKind> Placeable, IReadOnlyList<DecoyKind> Held,
    bool Listening = false, bool CanEnroll = false, bool NeedsVerification = false)
{
    public bool Removable => Placed.Count > 0 || Held.Count > 0 || NeedsVerification;

    /// <param name="admin">The service's confirmed placements and listener state when it answers.</param>
    public static DecoyCard Of(DecoySet? set, AdminDecoysStatus? admin = null)
    {
        var placed = set?.Placed ?? [];
        if (admin is { Held: true })
            return new([.. placed.OrderBy(p => p.Placed)], [], [.. admin.Kinds], Listening: admin.Listening, CanEnroll: placed.Count > 0);
        return new([.. placed.OrderBy(p => p.Placed)], [.. Enum.GetValues<DecoyKind>().Where(k => placed.All(p => p.Kind != k))], [],
            CanEnroll: admin is not null && (placed.Count > 0 || admin.NeedsVerification), NeedsVerification: admin?.NeedsVerification == true);
    }

    /// <summary>The string keys naming a kind on the card, and its link to place one.</summary>
    public static (string Name, string Place) Keys(DecoyKind kind) => kind switch
    {
        DecoyKind.PasswordsFile => ("Decoys_Passwords", "Decoys_Passwords_Place"),
        DecoyKind.Project => ("Decoys_Project", "Decoys_Project_Place"),
        _ => ("Decoys_Variables", "Decoys_Variables_Place"),
    };
}
