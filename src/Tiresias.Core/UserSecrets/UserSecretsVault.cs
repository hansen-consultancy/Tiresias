using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tiresias.Protocol;
using Tiresias.Vault;

namespace Tiresias.UserSecrets;

/// <summary>What the agent learned from one <c>secrets.json</c>, before asking the user anything.</summary>
/// <param name="Document">The secrets as the app will receive them, nesting kept.</param>
/// <param name="Keys">Flattened configuration keys of <see cref="Document"/>, for the consent screen. Never values.</param>
/// <param name="PlaintextKeys">Keys that are on disk in clear right now and will be sealed: the whole file on first conversion, or what <c>dotnet user-secrets set</c> added since.</param>
/// <param name="Version">The sealed version this document was read from; 0 for a plain file.</param>
public sealed record UserSecretsLoad(JsonObject Document, IReadOnlyList<string> Keys, IReadOnlyList<string> PlaintextKeys, int Version)
{
    /// <summary>The file holds plaintext that sealing would remove.</summary>
    public bool NeedsSealing => PlaintextKeys.Count > 0;
}

/// <summary>
/// The agent's side of protected user secrets: opening a <c>secrets.json</c> in any of its states,
/// and sealing a document back into it. The document is sealed whole, as JSON, under the slug
/// <c>usersecrets/&lt;id&gt;</c>, so structure survives and one secrets folder's ciphertext can't
/// be moved into another's.
/// </summary>
public static class UserSecretsVault
{
    static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public static string Slug(string userSecretsId) => $"usersecrets/{userSecretsId}";

    /// <summary>
    /// Reads a file's text into the document the app should get. Plain keys written beside a sealed
    /// envelope win over the sealed ones: they are the newer edit.
    /// </summary>
    /// <exception cref="InvalidDataException">The file is not JSON, or the envelope does not open with <paramref name="wrapper"/>.</exception>
    public static UserSecretsLoad Open(string userSecretsId, string? fileText, IKeyWrapper wrapper)
    {
        switch (SecretsFile.Classify(fileText))
        {
            case SecretsFileKind.None:
                return new(new JsonObject(), [], [], 0);
            case SecretsFileKind.Plain:
            {
                var plain = ParseObject(fileText!);
                var keys = FlattenKeys(plain);
                return new(plain, keys, keys, 0);
            }
            case SecretsFileKind.Sealed:
            {
                var (blob, additions) = SecretsFile.Read(fileText!);
                var (document, version) = Unseal(userSecretsId, blob, wrapper);
                if (additions is not null)
                    Merge(document, additions);
                return new(document, FlattenKeys(document), additions is null ? [] : FlattenKeys(additions), version);
            }
            default:
                throw new InvalidDataException("secrets.json is not valid JSON.");
        }
    }

    /// <summary>The file text for <paramref name="document"/> sealed as <paramref name="version"/>; callers pass the loaded version + 1.</summary>
    public static string Seal(string userSecretsId, int version, JsonObject document, IEnumerable<IKeyWrapper> wrappers)
    {
        var plaintext = Encoding.UTF8.GetBytes(document.ToJsonString());
        try
        {
            var secret = SecretEnvelope.Seal(Slug(userSecretsId), version, plaintext, wrappers);
            var blob = JsonSerializer.SerializeToUtf8Bytes(
                new BlobDto(secret.Version, new Dictionary<string, byte[]>(secret.WrappedDeks), secret.Nonce, secret.Ciphertext), Web);
            return SecretsFile.Write(blob);
        }
        finally
        {
            Array.Clear(plaintext);
        }
    }

    /// <summary>Configuration keys as <c>IConfiguration</c> would name them: <c>a:b</c> for nesting, <c>a:0</c> for array items.</summary>
    public static IReadOnlyList<string> FlattenKeys(JsonNode? node)
    {
        var keys = new List<string>();
        Walk(node, null, keys);
        return keys;

        static void Walk(JsonNode? node, string? prefix, List<string> keys)
        {
            switch (node)
            {
                case JsonObject obj when obj.Count > 0:
                    foreach (var (name, child) in obj)
                        Walk(child, prefix is null ? name : $"{prefix}:{name}", keys);
                    break;
                case JsonArray array when array.Count > 0:
                    for (var i = 0; i < array.Count; i++)
                        Walk(array[i], $"{prefix}:{i}", keys);
                    break;
                default:
                    if (prefix is not null)
                        keys.Add(prefix);
                    break;
            }
        }
    }

    /// <summary>Objects merge key by key; anything else in <paramref name="overlay"/> replaces what was there, arrays included (as configuration layering does).</summary>
    public static void Merge(JsonObject target, JsonObject overlay)
    {
        foreach (var (name, value) in overlay.ToArray())
        {
            if (value is JsonObject child && target[name] is JsonObject existing)
            {
                Merge(existing, child);
                continue;
            }
            target[name] = value?.DeepClone();
        }
    }

    static (JsonObject Document, int Version) Unseal(string userSecretsId, byte[] blob, IKeyWrapper wrapper)
    {
        var dto = JsonSerializer.Deserialize<BlobDto>(blob, Web) ?? throw new InvalidDataException("Sealed envelope is empty.");
        var secret = new SealedSecret(Slug(userSecretsId), dto.Version, dto.WrappedDeks, dto.Nonce, dto.Ciphertext);
        var dek = SecretEnvelope.UnwrapDek(secret, wrapper)
            ?? throw new InvalidDataException($"The sealed secrets do not open with key '{wrapper.Id}' (another user's, another folder's, or tampered with).");
        try
        {
            var plaintext = SecretEnvelope.Open(secret, dek) ?? throw new InvalidDataException("The sealed secrets were tampered with.");
            try
            {
                return (ParseObject(Encoding.UTF8.GetString(plaintext)), dto.Version);
            }
            finally
            {
                Array.Clear(plaintext);
            }
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    static JsonObject ParseObject(string json) =>
        JsonNode.Parse(json, documentOptions: Lenient) as JsonObject ?? throw new InvalidDataException("secrets.json is not a JSON object.");

    sealed record BlobDto(int Version, Dictionary<string, byte[]> WrappedDeks, byte[] Nonce, byte[] Ciphertext);
}
