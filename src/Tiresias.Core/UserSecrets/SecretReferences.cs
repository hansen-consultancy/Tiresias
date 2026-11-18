using System.Text.Json.Nodes;

namespace Tiresias.UserSecrets;

/// <summary>
/// A <c>secrets.json</c> value that names a credential for the agent to fetch at load time instead
/// of holding one: <c>tiresias:sql/{instance}/{grant}</c> becomes the lease's temporary SQL login,
/// <c>tiresias:raven/{instance}</c> (or <c>/{grant}</c>, the most the app may use) a RavenDB URL on
/// this PC that carries a placeholder.
/// </summary>
/// <param name="Grant">Always set for <see cref="Sql"/>; for <see cref="Raven"/>, <c>null</c> lets every grant through.</param>
public sealed record SecretReference(string Kind, string Service, string? Grant)
{
    public const string Sql = "sql";
    public const string Raven = "raven";

    public override string ToString() => $"{SecretReferences.Prefix}{Kind}/{Service}" + (Grant is null ? "" : $"/{Grant}");
}

/// <param name="ExpiresAt">When the value stops working, or <c>null</c> when it doesn't expire.</param>
public sealed record ResolvedSecret(string Value, DateTimeOffset? ExpiresAt);

/// <summary>Fetches what a <see cref="SecretReference"/> names. The app's agent asks the broker; nothing else can.</summary>
public interface ISecretReferenceResolver
{
    /// <param name="caller">The program loading the secrets, for the broker's audit.</param>
    /// <exception cref="InvalidOperationException">It can't be fetched; the message says why.</exception>
    Task<ResolvedSecret> ResolveAsync(SecretReference reference, string? caller, string userSecretsId, CancellationToken ct);
}

public static class SecretReferences
{
    public const string Prefix = Tiresias.Protocol.SecretsFile.ReferencePrefix;

    /// <summary>How far into a value's life the provider fetches a new one, so old and new overlap.</summary>
    const double RenewAtFraction = 0.8;

    /// <returns><c>null</c> for an ordinary value.</returns>
    /// <exception cref="InvalidDataException">The value starts with <c>tiresias:</c> but isn't a reference Tiresias knows.</exception>
    public static SecretReference? Parse(string value)
    {
        if (!value.StartsWith(Prefix, StringComparison.Ordinal))
            return null;
        return value[Prefix.Length..].Split('/') switch
        {
            [SecretReference.Sql, { Length: > 0 } service, { Length: > 0 } grant] => new(SecretReference.Sql, service, grant),
            [SecretReference.Raven, { Length: > 0 } service] => new(SecretReference.Raven, service, null),
            [SecretReference.Raven, { Length: > 0 } service, { Length: > 0 } grant] => new(SecretReference.Raven, service, grant),
            _ => throw new InvalidDataException(
                $"'{value}' is not a Tiresias reference. The kinds there are: tiresias:sql/<service>/<grant> and tiresias:raven/<service>[/<grant>]."),
        };
    }

    /// <summary>Every string value in the document that is a reference, with its configuration key (<c>ConnectionStrings:Default</c>).</summary>
    public static IReadOnlyList<(string Key, SecretReference Reference)> Find(JsonNode document)
    {
        var found = new List<(string, SecretReference)>();
        Walk(document, "", (key, value, _) =>
        {
            if (Parse(value) is { } reference)
                found.Add((key, reference));
        });
        return found;
    }

    /// <summary>
    /// Replaces every reference in <paramref name="document"/>, in place, with what
    /// <paramref name="resolve"/> fetches for it.
    /// </summary>
    /// <returns>When to fetch again: <see cref="RenewAtFraction"/> of the way to the earliest expiry, or <c>null</c> when nothing expires.</returns>
    public static async Task<DateTimeOffset?> ResolveAsync(JsonNode document, DateTimeOffset now,
        Func<string, SecretReference, Task<ResolvedSecret>> resolve)
    {
        var slots = new List<(string Key, SecretReference Reference, Action<string> Set)>();
        Walk(document, "", (key, value, set) =>
        {
            if (Parse(value) is { } reference)
                slots.Add((key, reference, set));
        });

        DateTimeOffset? earliest = null;
        foreach (var (key, reference, set) in slots)
        {
            var resolved = await resolve(key, reference);
            set(resolved.Value);
            if (resolved.ExpiresAt is { } expires && (earliest is null || expires < earliest))
                earliest = expires;
        }
        return earliest is { } at ? RenewAt(now, at) : null;
    }

    public static DateTimeOffset RenewAt(DateTimeOffset now, DateTimeOffset expiresAt) =>
        expiresAt <= now ? now : now + (expiresAt - now) * RenewAtFraction;

    static void Walk(JsonNode node, string key, Action<string, string, Action<string>> visit)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, child) in obj.ToArray())
                    Visit(child, Join(key, name), v => obj[name] = v, visit);
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    var index = i;
                    Visit(array[i], Join(key, i.ToString(System.Globalization.CultureInfo.InvariantCulture)), v => array[index] = v, visit);
                }
                break;
        }
    }

    static void Visit(JsonNode? child, string key, Action<string> set, Action<string, string, Action<string>> visit)
    {
        if (child is JsonValue value && value.TryGetValue<string>(out var text))
            visit(key, text, set);
        else if (child is not null)
            Walk(child, key, visit);
    }

    static string Join(string key, string name) => key.Length == 0 ? name : $"{key}:{name}";
}
