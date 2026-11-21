using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NSec.Cryptography;

namespace Tiresias.Access;

/// <summary>
/// One operation the user approved, exactly as the broker will carry it out: the broker builds the
/// placeholder, elevation or token from these fields alone, so nothing approved can be widened in
/// transit. Signed with the lease's approval key (<see cref="ApprovalKey"/>), which only an unlocked
/// agent or a fresh Hello prompt can derive.
/// </summary>
/// <param name="Op"><see cref="MintOp"/>, <see cref="ElevateOp"/> or <see cref="TokenOp"/>.</param>
/// <param name="Grant">The ceiling for a mint (<c>null</c> = every grant), the grant for an elevation, <c>null</c> for a token.</param>
/// <param name="Seconds">How long the placeholder or elevation lasts; 0 for a token, whose lifetime GitHub sets.</param>
/// <param name="IssuedAt">Unix seconds; the broker accepts it within <see cref="Transport.RequestSignature"/>'s window.</param>
/// <param name="Nonce">Random, so the broker can refuse a replay.</param>
public sealed record Approval(
    string Op,
    string LeaseId,
    string Service,
    string? Grant,
    long Seconds,
    string Consumer,
    string Purpose,
    string? Observed,
    long IssuedAt,
    string Nonce)
{
    public const string MintOp = "mint";
    public const string ElevateOp = "elevate";
    public const string TokenOp = "token";

    const string Tag = "tiresias/v1/approval";

    public static Approval ForMint(string leaseId, AccessRequest request, DateTimeOffset now) =>
        new(MintOp, leaseId, request.ServiceSlug, request.Ceiling, (long)request.Duration.TotalSeconds,
            request.Consumer, request.Purpose, request.ObservedProcess, now.ToUnixTimeSeconds(), NewNonce());

    public static Approval ForElevate(string leaseId, string service, string grant, TimeSpan duration, string consumer, DateTimeOffset now) =>
        new(ElevateOp, leaseId, service, grant, (long)duration.TotalSeconds, consumer, $"elevate {service}/{grant}", null, now.ToUnixTimeSeconds(), NewNonce());

    public static Approval ForToken(string leaseId, string service, string consumer, string purpose, DateTimeOffset now) =>
        new(TokenOp, leaseId, service, null, 0, consumer, purpose, null, now.ToUnixTimeSeconds(), NewNonce());

    /// <summary>The placeholder request a mint approval stands for.</summary>
    public AccessRequest ToAccessRequest() => new(Consumer, Observed, Service, Grant, Purpose, TimeSpan.FromSeconds(Seconds));

    public SignedApproval Sign(Key approvalKey)
    {
        var bytes = Canonical();
        return new(bytes, SignatureAlgorithm.Ed25519.Sign(approvalKey, bytes));
    }

    /// <summary>
    /// Compact JSON array, so a purpose holding a newline or a quote can't be read two ways:
    /// <c>["tiresias/v1/approval",op,leaseId,service,grant,seconds,consumer,purpose,observed,issuedAt,nonce]</c>.
    /// </summary>
    public byte[] Canonical()
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartArray();
            json.WriteStringValue(Tag);
            json.WriteStringValue(Op);
            json.WriteStringValue(LeaseId);
            json.WriteStringValue(Service);
            Nullable(json, Grant);
            json.WriteNumberValue(Seconds);
            json.WriteStringValue(Consumer);
            json.WriteStringValue(Purpose);
            Nullable(json, Observed);
            json.WriteNumberValue(IssuedAt);
            json.WriteStringValue(Nonce);
            json.WriteEndArray();
        }
        return buffer.ToArray();
    }

    /// <summary>The approval these bytes are the canonical form of, or <c>null</c> when they are anything else.</summary>
    public static Approval? Parse(byte[] canonical)
    {
        try
        {
            using var document = JsonDocument.Parse(canonical);
            var a = document.RootElement;
            if (a.ValueKind != JsonValueKind.Array || a.GetArrayLength() != 11 || a[0].GetString() != Tag)
                return null;
            var approval = new Approval(a[1].GetString()!, a[2].GetString()!, a[3].GetString()!, NullableString(a[4]), a[5].GetInt64(),
                a[6].GetString()!, a[7].GetString()!, NullableString(a[8]), a[9].GetInt64(), a[10].GetString()!);
            return approval.Canonical().AsSpan().SequenceEqual(canonical) ? approval : null;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException or NullReferenceException)
        {
            return null;
        }
    }

    static string? NullableString(JsonElement e) => e.ValueKind == JsonValueKind.Null ? null : e.GetString()!;

    static void Nullable(Utf8JsonWriter json, string? value)
    {
        if (value is null)
            json.WriteNullValue();
        else
            json.WriteStringValue(value);
    }

    static string NewNonce() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}

/// <summary>An approval as it travels: its canonical bytes and the approval key's signature over them.</summary>
public sealed record SignedApproval(byte[] Approval, byte[] Signature)
{
    /// <returns>The approval, when the signature verifies under <paramref name="approvalKey"/>; otherwise <c>null</c>.</returns>
    public Approval? Verify(PublicKey approvalKey) =>
        Approval is { } bytes && Signature is { } signature && SignatureAlgorithm.Ed25519.Verify(approvalKey, bytes, signature)
            ? Access.Approval.Parse(bytes)
            : null;
}

/// <summary>
/// The lease's approval key: an Ed25519 key derived from the Hello wrap (its approval root) and the
/// lease id. The same Hello credential always derives the same key for a lease, and a new lease a
/// different one, so an approval key never outlives its lease. The broker learns its public half
/// only from a seal whose DEKs open the vault's secrets.
/// </summary>
public static class ApprovalKey
{
    public static Key Derive(byte[] root, string leaseId)
    {
        var seed = HKDF.DeriveKey(HashAlgorithmName.SHA256, root, 32, salt: [], info: Encoding.UTF8.GetBytes($"tiresias/v1/approval\n{leaseId}"));
        try
        {
            return Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        }
        finally
        {
            Array.Clear(seed);
        }
    }

    /// <summary>The raw public key, as <c>/lease/seal</c> carries it.</summary>
    public static byte[] Public(Key key) => key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
}
