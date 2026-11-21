using Tiresias.AdminTier;
using Tiresias.Decoys;

namespace Tiresias.App.Logic;

/// <summary>
/// Home's decoys card: what is placed, and which kinds can still be placed from the app (each once,
/// at its default place; another place is <c>tir decoys place</c>'s). When the admin tier holds the
/// set, only its kinds are known (<see cref="Held"/>), and nothing more is placed beside it.
/// </summary>
public sealed record DecoyCard(IReadOnlyList<PlacedDecoy> Placed, IReadOnlyList<DecoyKind> Placeable, IReadOnlyList<DecoyKind> Held)
{
    public bool Removable => Placed.Count > 0 || Held.Count > 0;

    /// <param name="admin">The admin tier's <c>decoys.status</c>, when it answers; read only when <paramref name="set"/> is gone.</param>
    public static DecoyCard Of(DecoySet? set, AdminDecoysStatus? admin = null)
    {
        if (set is null && admin is { Held: true })
            return new([], [], [.. admin.Kinds]);
        var placed = set?.Placed ?? [];
        return new([.. placed.OrderBy(p => p.Placed)], [.. Enum.GetValues<DecoyKind>().Where(k => placed.All(p => p.Kind != k))], []);
    }

    /// <summary>The string keys naming a kind on the card, and its link to place one.</summary>
    public static (string Name, string Place) Keys(DecoyKind kind) => kind switch
    {
        DecoyKind.PasswordsFile => ("Decoys_Passwords", "Decoys_Passwords_Place"),
        DecoyKind.Project => ("Decoys_Project", "Decoys_Project_Place"),
        _ => ("Decoys_Variables", "Decoys_Variables_Place"),
    };
}
