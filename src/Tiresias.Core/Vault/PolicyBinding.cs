using System.Security.Cryptography;
using System.Text.Json;
using Tiresias.Policy;

namespace Tiresias.Vault;

/// <summary>
/// The policy a vault secret may be used under, as canonical bytes: every grant whose
/// <see cref="Grant.SecretSlug"/> is that secret, with its service's slug and upstream, its position
/// (ceilings are positional), rule and flags, in vault order. A bound secret's ciphertext carries the
/// hash of this as associated data (<see cref="SecretEnvelope"/>), so it opens only under the policy
/// it was sealed for: editing an upstream, widening a rule or pointing another grant at the secret
/// makes it unusable until someone who can open its DEK approves the change
/// (<see cref="SecretEnvelope.Rebind"/>).
/// </summary>
public static class PolicyBinding
{
    /// <summary>SHA-256 of the canonical policy of <paramref name="secretSlug"/> in <paramref name="vault"/>.</summary>
    public static byte[] Hash(VaultDocument vault, string secretSlug) =>
        SHA256.HashData(Canonical(vault.Services, grant => grant.SecretSlug == secretSlug));

    /// <summary>
    /// Whether <paramref name="secret"/> may be used under <paramref name="vault"/>'s policy: it is
    /// unbound, or the policy approved for it is the one in force.
    /// </summary>
    public static bool Allows(VaultDocument vault, SealedSecret secret) =>
        secret.PolicyHash is not { } approved || approved.AsSpan().SequenceEqual(Hash(vault, secret.Slug));

    /// <summary>SHA-256 of one service's whole policy, for noticing that it changed.</summary>
    public static byte[] ServiceHash(Service service) =>
        SHA256.HashData(Canonical([service], _ => true));

    /// <summary>The bytes <see cref="Hash"/> hashes. Exposed so tests can pin the format.</summary>
    public static byte[] For(VaultDocument vault, string secretSlug) =>
        Canonical(vault.Services, grant => grant.SecretSlug == secretSlug);

    static byte[] Canonical(IEnumerable<Service> services, Func<Grant, bool> include)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartArray();
            json.WriteStringValue("tiresias/v1/policy-binding");
            foreach (var service in services)
            {
                for (var index = 0; index < service.Grants.Count; index++)
                {
                    var grant = service.Grants[index];
                    if (!include(grant))
                        continue;
                    json.WriteStartArray();
                    json.WriteStringValue(service.Slug);
                    json.WriteStringValue(service.Upstream.OriginalString);
                    json.WriteNumberValue(index);
                    json.WriteStringValue(grant.Name);
                    json.WriteStringValue(grant.SecretSlug);
                    Strings(json, grant.Rule.Methods.Order(StringComparer.Ordinal));
                    Strings(json, grant.Rule.Allow.Select(r => r.ToString()));
                    Strings(json, (grant.Rule.Deny ?? []).Select(r => r.ToString()));
                    if (grant.Rule.MaxBodyBytes is { } max)
                        json.WriteNumberValue(max);
                    else
                        json.WriteNullValue();
                    json.WriteBooleanValue(grant.RequiresElevation);
                    json.WriteBooleanValue(grant.IssuesLogins);
                    json.WriteEndArray();
                }
            }
            json.WriteEndArray();
        }
        return buffer.ToArray();
    }

    static void Strings(Utf8JsonWriter json, IEnumerable<string> values)
    {
        json.WriteStartArray();
        foreach (var value in values)
            json.WriteStringValue(value);
        json.WriteEndArray();
    }
}
