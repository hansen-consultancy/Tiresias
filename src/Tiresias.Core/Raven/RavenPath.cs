using Tiresias.Access;

namespace Tiresias.Raven;

/// <summary>
/// A RavenDB client is pointed at <c>/raven/{instance}/{placeholder}</c>, because it sends no custom
/// header on its WebSocket connections and so can't carry the placeholder as <c>Authorization</c>.
/// The placeholder is the first segment after the instance; everything after it is the node's path.
/// </summary>
public static class RavenPath
{
    /// <param name="remainder">The raw target after <c>/raven/{instance}</c>, e.g. <c>/tirph_x/databases/Orders/docs?id=1</c>.</param>
    /// <returns>
    /// The placeholder (or <c>null</c> when the first segment isn't one, and the request carries its
    /// placeholder in a header instead) and the path and query the node sees.
    /// </returns>
    public static (string? Placeholder, string PathAndQuery) Split(string remainder)
    {
        if (!remainder.StartsWith("/" + PlaceholderToken.Prefix, StringComparison.Ordinal))
            return (null, remainder);
        var end = remainder.IndexOfAny(['/', '?'], 1);
        var placeholder = end < 0 ? remainder[1..] : remainder[1..end];
        var rest = end < 0 ? "/" : remainder[end] == '?' ? "/" + remainder[end..] : remainder[end..];
        return (placeholder, rest);
    }
}
