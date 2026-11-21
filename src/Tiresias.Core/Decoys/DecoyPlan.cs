namespace Tiresias.Decoys;

/// <summary>A file to write, or a user variable to set, to place one decoy.</summary>
public abstract record DecoyStep;

public sealed record WriteDecoyFile(string Path, string Content) : DecoyStep;

public sealed record SetDecoyVariable(string Name, string Value) : DecoyStep;

/// <summary>
/// What placing a decoy writes. Tiresias only ever creates: a file, a folder or a variable that
/// already exists is refused, so a decoy never lands in something a real program reads.
/// </summary>
public static class DecoyPlan
{
    public const string PasswordsFileName = "passwords.txt";

    /// <summary>The user variables of <see cref="DecoyKind.Variables"/>.</summary>
    public static readonly string[] VariableNames = ["ADMIN_API_URL", "ADMIN_API_TOKEN"];

    /// <param name="where">The file (<see cref="DecoyKind.PasswordsFile"/>) or the new folder (<see cref="DecoyKind.Project"/>); ignored for variables.</param>
    /// <param name="exists">Whether a path exists, or a user variable is set.</param>
    /// <exception cref="InvalidOperationException">Something is already there.</exception>
    public static IReadOnlyList<DecoyStep> Steps(DecoySet set, DecoyKind kind, string where, Func<string, bool> exists)
    {
        IReadOnlyList<DecoyStep> steps = kind switch
        {
            DecoyKind.PasswordsFile => [new WriteDecoyFile(where, DecoyListText(set))],
            DecoyKind.Project =>
            [
                new WriteDecoyFile(Path.Combine(where, "appsettings.Production.json"), AppSettings(set)),
                new WriteDecoyFile(Path.Combine(where, ".env"), DotEnv(set)),
            ],
            DecoyKind.Variables => [new SetDecoyVariable(VariableNames[0], set.HttpUrl + "/admin"), new SetDecoyVariable(VariableNames[1], set.Values.AdminToken)],
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var taken = kind == DecoyKind.Project && exists(where) ? where
            : steps.Select(s => s switch { WriteDecoyFile f => f.Path, SetDecoyVariable v => v.Name, _ => "" }).FirstOrDefault(exists);
        if (taken is not null)
            throw new InvalidOperationException($"{taken} already exists. Decoys are only placed where nothing is, so no real program reads one.");
        return steps;
    }

    /// <summary>
    /// What removing a decoy deletes or clears: each of its files or variables that still holds
    /// exactly what was placed. One that is gone needs nothing; one the user changed is theirs now
    /// and is kept, by path or name.
    /// </summary>
    /// <param name="current">A file's text or a user variable's value now, or <c>null</c> when it is gone.</param>
    public static (IReadOnlyList<DecoyStep> Remove, IReadOnlyList<string> Kept) Undo(DecoySet set, PlacedDecoy placed, Func<string, string?> current)
    {
        var remove = new List<DecoyStep>();
        var kept = new List<string>();
        foreach (var step in Steps(set, placed.Kind, placed.Where, _ => false))
        {
            var (target, content) = step switch
            {
                WriteDecoyFile f => (f.Path, f.Content),
                SetDecoyVariable v => (v.Name, v.Value),
                _ => throw new InvalidOperationException(),
            };
            var now = current(target);
            if (now == content)
                remove.Add(step);
            else if (now is not null)
                kept.Add(target);
        }
        return (remove, kept);
    }

    public static string DecoyListText(DecoySet set) => $"""
        Billing database (production)
        {set.ConnectionString}

        Admin portal
        {set.HttpUrl}/admin
        token: {set.Values.AdminToken}

        OpenAI (billing assistant)
        base url: {set.HttpUrl}/v1
        key: {set.Values.ApiKey}

        """;

    public static string AppSettings(DecoySet set) => $$"""
        {
          "ConnectionStrings": {
            "Billing": "{{set.ConnectionString}}"
          },
          "RavenDB": {
            "Urls": [ "{{set.HttpUrl}}" ],
            "Database": "Billing"
          },
          "AdminApi": {
            "Url": "{{set.HttpUrl}}/admin",
            "Token": "{{set.Values.AdminToken}}"
          }
        }

        """;

    public static string DotEnv(DecoySet set) => $"""
        ADMIN_API_URL={set.HttpUrl}/admin
        ADMIN_API_TOKEN={set.Values.AdminToken}
        OPENAI_BASE_URL={set.HttpUrl}/v1
        OPENAI_API_KEY={set.Values.ApiKey}

        """;
}
