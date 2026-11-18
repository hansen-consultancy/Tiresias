using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Tiresias.EnvironmentVariables;

/// <summary>One sealed variable. <paramref name="Expandable"/> is kept so Put back writes it as the registry had it (<c>REG_EXPAND_SZ</c>).</summary>
public sealed record SealedVariable(string Name, string Value, bool Expandable = false);

/// <summary>
/// Environment variables taken out of the user's Windows environment and sealed: which names look
/// like secrets, and the document they are sealed as. Names are compared as Windows does, ignoring
/// case. Nothing here reads the registry or a value from it.
/// </summary>
public static partial class SealedVariables
{
    /// <summary>Set by Windows or by installers, and never a secret even when a word in the name matches.</summary>
    static readonly HashSet<string> NeverOffered = new(StringComparer.OrdinalIgnoreCase)
    {
        "Path", "PATHEXT", "PSModulePath", "TEMP", "TMP", "OneDrive", "OneDriveCommercial", "OneDriveConsumer",
        "USERNAME", "USERPROFILE", "USERDOMAIN", "HOMEPATH", "HOMEDRIVE", "APPDATA", "LOCALAPPDATA",
    };

    /// <summary>
    /// Whether a user variable is probably a secret: its name says so (key, token, secret, password,
    /// credential, connection string) and its value is not a path or a list. A path to a key file is
    /// not the key.
    /// </summary>
    public static bool LooksSecret(string name, int valueLength, bool valueIsPath) =>
        valueLength > 0 && !valueIsPath && !NeverOffered.Contains(name) && SecretName().IsMatch(name);

    /// <summary>A value that names a file or folder, or holds a <c>;</c> list: never sealed by default.</summary>
    public static bool IsPath(string value) =>
        value.Contains(';', StringComparison.Ordinal) || PathStart().IsMatch(value) || value.StartsWith('%', StringComparison.Ordinal);

    /// <summary>The document a set of variables is sealed as. Order is kept; a later duplicate name wins.</summary>
    public static JsonObject ToDocument(IEnumerable<SealedVariable> variables)
    {
        var values = new JsonObject();
        var expandable = new JsonArray();
        foreach (var variable in Distinct(variables))
        {
            values[variable.Name] = variable.Value;
            if (variable.Expandable)
                expandable.Add(variable.Name);
        }
        var document = new JsonObject { ["variables"] = values };
        if (expandable.Count > 0)
            document["expandable"] = expandable;
        return document;
    }

    /// <exception cref="InvalidDataException">The document is not one <see cref="ToDocument"/> wrote.</exception>
    public static IReadOnlyList<SealedVariable> FromDocument(JsonObject document)
    {
        if (document.Count == 0)
            return [];
        if (document["variables"] is not JsonObject values)
            throw new InvalidDataException("The sealed environment has no variables.");
        var expandable = (document["expandable"] as JsonArray ?? [])
            .Select(n => (string?)n).OfType<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. values.Select(pair => new SealedVariable(pair.Key,
            pair.Value?.GetValue<string>() ?? throw new InvalidDataException($"The sealed variable {pair.Key} has no value."),
            expandable.Contains(pair.Key)))];
    }

    /// <summary><paramref name="variables"/> with <paramref name="added"/> replacing any of the same name.</summary>
    public static IReadOnlyList<SealedVariable> With(IEnumerable<SealedVariable> variables, IEnumerable<SealedVariable> added) =>
        Distinct(variables.Concat(added));

    public static IReadOnlyList<SealedVariable> Without(IEnumerable<SealedVariable> variables, IEnumerable<string> names)
    {
        var removed = names.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. variables.Where(v => !removed.Contains(v.Name))];
    }

    static SealedVariable[] Distinct(IEnumerable<SealedVariable> variables)
    {
        var byName = new Dictionary<string, SealedVariable>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        foreach (var variable in variables)
        {
            if (!byName.ContainsKey(variable.Name))
                order.Add(variable.Name);
            byName[variable.Name] = variable;
        }
        return [.. order.Select(n => byName[n])];
    }

    [GeneratedRegex(@"KEY|TOKEN|SECRET|PASSW(OR)?D|PWD|CREDENTIAL|CONNECTION_?STRING", RegexOptions.IgnoreCase)]
    private static partial Regex SecretName();

    [GeneratedRegex(@"^([A-Za-z]:[\\/]|\\\\|/)")]
    private static partial Regex PathStart();
}
