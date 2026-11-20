using System.Text.Json;
using System.Text.Json.Nodes;
using Tiresias.Protocol;

namespace Tiresias.UserSecrets;

/// <summary>What a <c>secrets.json</c> holds, as the secrets editor and <c>tir doctor</c> both judge it.</summary>
public enum SecretsContent
{
    /// <summary>No keys: no file, whitespace, <c>{}</c>, comments only, or a sealed document with nothing in it.</summary>
    Empty,
    /// <summary>Keys whose every value is a shape that can't be a credential.</summary>
    Settings,
    /// <summary>At least one value that may be a credential; also any sealed file not opened.</summary>
    Secrets,
    /// <summary>Not a JSON object.</summary>
    Invalid,
}

/// <summary>
/// Sorts a secrets file by what it holds, reading values only to judge their shape, never to keep or
/// show them. A doubtful value counts as a secret: a hidden key costs more than one warning too many.
/// </summary>
public static class SecretsContents
{
    static readonly string[] LogLevels = ["Trace", "Debug", "Information", "Warning", "Error", "Critical", "None"];

    /// <summary>
    /// A file's content from its text alone. A sealed file is <see cref="SecretsContent.Secrets"/>:
    /// whether it is empty is known only once it is opened (<see cref="Of(JsonNode?)"/>).
    /// </summary>
    public static SecretsContent OfFile(string? text) => SecretsFile.Classify(text) switch
    {
        SecretsFileKind.None => SecretsContent.Empty,
        SecretsFileKind.Plain => Of(JsonNode.Parse(text!, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })),
        SecretsFileKind.Sealed => SecretsContent.Secrets,
        _ => SecretsContent.Invalid,
    };

    /// <summary>An opened document's content: the plain file's, or the sealed one's once unsealed.</summary>
    public static SecretsContent Of(JsonNode? document)
    {
        if (document is not JsonObject root || root.Count == 0)
            return SecretsContent.Empty;
        return Leaves(root, null).All(leaf => IsSetting(leaf.Key, leaf.Value)) ? SecretsContent.Settings : SecretsContent.Secrets;
    }

    static IEnumerable<(string Key, JsonNode? Value)> Leaves(JsonNode? node, string? key)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, child) in obj)
                    foreach (var leaf in Leaves(child, key is null ? name : $"{key}:{name}"))
                        yield return leaf;
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                    foreach (var leaf in Leaves(array[i], $"{key}:{i}"))
                        yield return leaf;
                break;
            default:
                yield return (key!, node);
                break;
        }
    }

    static bool IsSetting(string key, JsonNode? value)
    {
        if (value is null)
            return true;
        switch (value.GetValueKind())
        {
            case JsonValueKind.True or JsonValueKind.False or JsonValueKind.Number or JsonValueKind.Null:
                return true;
            case JsonValueKind.String:
                var text = value.GetValue<string>();
                return text.Length == 0
                    || (key.StartsWith("Logging:", StringComparison.OrdinalIgnoreCase) && LogLevels.Contains(text, StringComparer.OrdinalIgnoreCase))
                    || IsPlainUrl(text);
            default:
                return false;
        }
    }

    /// <summary>
    /// An address with nowhere to hide a credential: no user info, no query or fragment, and no path
    /// segment long enough to be a token (as in a webhook's <c>/services/T0/B0/xyz...</c>).
    /// </summary>
    static bool IsPlainUrl(string text) =>
        Uri.TryCreate(text, UriKind.Absolute, out var uri)
        && uri.Scheme is "http" or "https"
        && uri.UserInfo.Length == 0
        && uri.Query.Length == 0
        && uri.Fragment.Length == 0
        && uri.Segments.All(s => s.TrimEnd('/').Length < 20);
}
