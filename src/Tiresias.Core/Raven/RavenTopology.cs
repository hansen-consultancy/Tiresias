using System.Text.Json.Nodes;

namespace Tiresias.Raven;

/// <summary>
/// Keeps a RavenDB client on the broker. The client learns node URLs from topology responses and
/// then talks to those nodes directly, which would bypass the proxy and, from loopback http, trip
/// the client's rule that every node shares the first URL's scheme. Rewriting every node URL to the
/// proxy's own base fixes both with no consumer code: the client sees N nodes at one address and
/// the broker reaches whichever node the upstream URL names. Per-node failover is lost, deliberately.
/// </summary>
public static class RavenTopology
{
    static readonly HashSet<string> NodeMaps = new(StringComparer.Ordinal) { "AllNodes", "Members", "Promotables", "Watchers" };

    /// <summary>The database topology (<c>/topology?name=db</c>) and the cluster topology (<c>/cluster/topology</c>).</summary>
    public static bool IsTopologyPath(string pathAndQuery)
    {
        var query = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
        var path = query < 0 ? pathAndQuery : pathAndQuery[..query];
        return path is "/topology" or "/cluster/topology";
    }

    /// <summary>
    /// Replaces every node URL in a topology body with <paramref name="publicBase"/>: each <c>Url</c>
    /// string, and each value of the <c>AllNodes</c>/<c>Members</c>/<c>Promotables</c>/<c>Watchers</c>
    /// tag → URL maps, at any depth. Anything that isn't JSON comes back unchanged.
    /// </summary>
    public static string Rewrite(string json, string publicBase)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json);
        }
        catch (System.Text.Json.JsonException)
        {
            return json;
        }
        if (root is null)
            return json;
        Visit(root, publicBase);
        return root.ToJsonString();
    }

    static void Visit(JsonNode node, string publicBase)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, value) in obj.ToArray())
                {
                    if (value is JsonValue v && v.TryGetValue<string>(out _) && name == "Url")
                        obj[name] = publicBase;
                    else if (value is JsonObject map && NodeMaps.Contains(name))
                    {
                        foreach (var (tag, url) in map.ToArray())
                            if (url is JsonValue u && u.TryGetValue<string>(out _))
                                map[tag] = publicBase;
                    }
                    else if (value is not null)
                        Visit(value, publicBase);
                }
                break;
            case JsonArray array:
                foreach (var item in array)
                    if (item is not null)
                        Visit(item, publicBase);
                break;
        }
    }
}
