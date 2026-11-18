using System.Text.Json.Nodes;

namespace Tiresias.UserSecrets;

/// <summary>
/// Changes to a user-secrets document by configuration key, as <c>dotnet user-secrets</c> makes them:
/// a key is stored flat (<c>"Db:Password": "…"</c>), and removing a key also finds it nested.
/// </summary>
public static class UserSecretsEdit
{
    /// <summary>Sets <paramref name="key"/>, replacing a nested value of the same configuration key so the two can't disagree.</summary>
    public static void Set(JsonObject document, string key, string value)
    {
        RemoveNested(document, key);
        document[key] = value;
    }

    /// <returns>Whether anything was removed.</returns>
    public static bool Remove(JsonObject document, string key)
    {
        var removed = document.Remove(key);
        return RemoveNested(document, key) || removed;
    }

    /// <summary>Removes <c>a:b:c</c> stored as <c>{ "a": { "b": { "c": … } } }</c> (or any flat/nested mix), case-insensitively like configuration keys.</summary>
    static bool RemoveNested(JsonObject node, string key)
    {
        foreach (var (name, child) in node.ToArray())
        {
            if (string.Equals(name, key, StringComparison.OrdinalIgnoreCase))
            {
                node.Remove(name);
                return true;
            }
            if (child is JsonObject inner && key.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)
                && RemoveNested(inner, key[(name.Length + 1)..]))
            {
                if (inner.Count == 0)
                    node.Remove(name);
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Every configuration key with its value as configuration would read it (numbers and booleans as
    /// their JSON text, <c>null</c> as empty), in document order. For an editor that shows one row per key.
    /// </summary>
    public static IReadOnlyList<KeyValuePair<string, string>> Flatten(JsonObject document)
    {
        var rows = new List<KeyValuePair<string, string>>();
        Walk(document, null);
        return rows;

        void Walk(JsonNode? node, string? prefix)
        {
            switch (node)
            {
                case JsonObject obj when obj.Count > 0:
                    foreach (var (name, child) in obj)
                        Walk(child, prefix is null ? name : $"{prefix}:{name}");
                    break;
                case JsonArray array when array.Count > 0:
                    for (var i = 0; i < array.Count; i++)
                        Walk(array[i], $"{prefix}:{i}");
                    break;
                case JsonValue value when prefix is not null:
                    rows.Add(new(prefix, value.TryGetValue<string>(out var text) ? text : value.ToJsonString()));
                    break;
                default:
                    if (prefix is not null)
                        rows.Add(new(prefix, ""));
                    break;
            }
        }
    }

    /// <summary>
    /// Applies an editor's result to the document it was opened from: keys gone from
    /// <paramref name="edited"/> are removed, new or changed ones set (flat), untouched ones keep
    /// their place and nesting.
    /// </summary>
    /// <returns>How many keys changed.</returns>
    public static int Apply(JsonObject document, IReadOnlyList<KeyValuePair<string, string>> edited)
    {
        var before = Flatten(document).ToDictionary(r => r.Key, r => r.Value, StringComparer.OrdinalIgnoreCase);
        var after = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in edited)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("A key can't be empty.", nameof(edited));
            if (!after.TryAdd(key.Trim(), value))
                throw new ArgumentException($"The key '{key.Trim()}' appears twice.", nameof(edited));
        }

        var changed = 0;
        foreach (var key in before.Keys.Where(k => !after.ContainsKey(k)))
            changed += Remove(document, key) ? 1 : 0;
        foreach (var (key, value) in after)
        {
            if (before.TryGetValue(key, out var old) && old == value)
                continue;
            Set(document, key, value);
            changed++;
        }
        return changed;
    }
}
