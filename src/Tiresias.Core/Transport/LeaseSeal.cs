using System.Text.Json;
using NSec.Cryptography;

namespace Tiresias.Transport;

/// <summary>Authenticates a batch of sealed data keys under the revision key enrolled with the broker service.</summary>
public static class LeaseSeal
{
    public static byte[] Sign(Key key, string leaseId, byte[] approvalKey, IReadOnlyDictionary<string, byte[]> deks) =>
        SignatureAlgorithm.Ed25519.Sign(key, Canonical(leaseId, approvalKey, deks));

    public static bool Verify(PublicKey key, string leaseId, byte[] approvalKey, IReadOnlyDictionary<string, byte[]> deks, byte[]? signature) =>
        signature?.Length == SignatureAlgorithm.Ed25519.SignatureSize &&
        SignatureAlgorithm.Ed25519.Verify(key, Canonical(leaseId, approvalKey, deks), signature);

    static byte[] Canonical(string leaseId, byte[] approvalKey, IReadOnlyDictionary<string, byte[]> deks)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartArray();
            json.WriteStringValue("tiresias/v1/lease-seal");
            json.WriteStringValue(leaseId);
            json.WriteBase64StringValue(approvalKey);
            json.WriteStartObject();
            foreach (var (slug, box) in deks.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                json.WriteBase64String(slug, box);
            json.WriteEndObject();
            json.WriteEndArray();
        }
        return buffer.ToArray();
    }
}
