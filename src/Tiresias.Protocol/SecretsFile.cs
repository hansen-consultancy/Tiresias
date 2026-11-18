using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tiresias.Protocol;

public enum SecretsFileKind
{
    /// <summary>No file, or an empty one.</summary>
    None,
    /// <summary>Ordinary user secrets: readable by anything running as this user.</summary>
    Plain,
    /// <summary>Holds the sealed envelope, possibly with plain keys added beside it since (<c>dotnet user-secrets set</c>).</summary>
    Sealed,
    /// <summary>Not JSON: something other than this library or the stock tools wrote it.</summary>
    Invalid,
}

/// <summary>
/// The format of a protected <c>secrets.json</c>. It stays valid JSON on purpose:
/// <c>WebApplication.CreateBuilder</c> parses the file inside the framework in Development, where no
/// interceptor can reach, and a non-JSON file would crash every app at startup. Code that is not
/// intercepted therefore loads only <c>$tiresias:v</c> and <c>$tiresias:sealed</c>, which are
/// ciphertext and useless, and none of the real keys.
/// </summary>
public static class SecretsFile
{
    public const string FileName = "secrets.json";

    public const string EnvelopeProperty = "$tiresias";

    public static SecretsFileKind Classify(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return SecretsFileKind.None;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return SecretsFileKind.Invalid;
            return doc.RootElement.TryGetProperty(EnvelopeProperty, out _) ? SecretsFileKind.Sealed : SecretsFileKind.Plain;
        }
        catch (JsonException)
        {
            return SecretsFileKind.Invalid;
        }
    }

    /// <summary>The file body for a sealed document: the envelope and nothing else.</summary>
    public static string Write(byte[] sealedBlob) =>
        new JsonObject
        {
            [EnvelopeProperty] = new JsonObject
            {
                ["v"] = 1,
                ["sealed"] = Convert.ToBase64String(sealedBlob),
            },
        }.ToJsonString(new JsonSerializerOptions { WriteIndented = true });

    /// <summary>The same sealed file with its envelope's blob replaced; plain keys written beside it stay.</summary>
    public static string WithSealed(string json, byte[] sealedBlob)
    {
        var root = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })?.AsObject()
            ?? throw new InvalidDataException("secrets.json is not a JSON object.");
        var envelope = root[EnvelopeProperty]?.AsObject() ?? throw new InvalidDataException("secrets.json has no sealed envelope.");
        envelope["sealed"] = Convert.ToBase64String(sealedBlob);
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Splits a sealed file into the envelope's blob and any plain keys written beside it since,
    /// which the agent merges in and seals.
    /// </summary>
    public static (byte[] Sealed, JsonObject? PlainAdditions) Read(string json)
    {
        var root = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })?.AsObject()
            ?? throw new InvalidDataException("secrets.json is not a JSON object.");
        var envelope = root[EnvelopeProperty]?.AsObject()
            ?? throw new InvalidDataException("secrets.json has no sealed envelope.");
        if ((int?)envelope["v"] != 1)
            throw new InvalidDataException($"Unsupported sealed secrets version '{envelope["v"]}'.");
        var blob = Convert.FromBase64String((string?)envelope["sealed"] ?? throw new InvalidDataException("Sealed envelope is empty."));

        root.Remove(EnvelopeProperty);
        return (blob, root.Count == 0 ? null : root);
    }
}
