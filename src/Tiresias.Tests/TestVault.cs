using Tiresias.Crypto;
using Tiresias.Policy;
using Tiresias.Transport;
using Tiresias.Vault;
using NSec.Cryptography;

namespace Tiresias.Tests;

/// <summary>
/// A vault with one service (<c>llm</c>: read GET, write POST, admin DELETE behind elevation), whose
/// DEKs are wrapped to an X25519 key standing in for the TPM. <see cref="SealTo"/> plays the
/// Keyring's part of a lease: unwrap each DEK and seal it to the broker's lease key.
/// <see cref="CreateWithSql"/> adds a SQL Server service, <c>appdb</c>, whose read and write grants
/// hold provisioner connection strings; <see cref="CreateWithRaven"/> a RavenDB one.
/// </summary>
sealed class TestVault : IDisposable
{
    readonly Key tpmKey = Key.Create(KeyAgreementAlgorithm.X25519);

    TestVault(Func<X25519KeyWrapper, (SealedSecret[] Secrets, Service[] Services)>? extra = null, bool bound = true)
    {
        Tpm = X25519KeyWrapper.ForKey("tpm", tpmKey);
        var (extraSecrets, extraServices) = extra?.Invoke(Tpm) ?? ([], []);
        Service[] services =
        [
            new Service("llm", new Uri("https://llm.example/"),
            [
                new Grant("read", "llm-read", Rule("GET", "^/v1/models")),
                new Grant("write", "llm-write", Rule("POST", "^/v1/")),
                new Grant("admin", "llm-admin", Rule("DELETE", "^/v1/"), RequiresElevation: true),
            ]),
            .. extraServices,
        ];
        var policy = new VaultDocument([], services);
        SealedSecret Seal(string slug, ReadOnlySpan<byte> value) =>
            SecretEnvelope.Seal(slug, 1, value, [Tpm], bound ? PolicyBinding.Hash(policy, slug) : null);
        Document = new(
            [
                Seal("llm-read", "Bearer sk-read"u8),
                Seal("llm-write", "Bearer sk-write"u8),
                Seal("llm-admin", "Bearer sk-admin"u8),
                .. extraSecrets.Select(s => bound ? Bind(s, policy) : s),
            ],
            services);
    }

    public X25519KeyWrapper Tpm { get; }
    public VaultDocument Document { get; }

    /// <summary>The <c>llm</c> vault, its secrets (extras too) bound to their policy (<see cref="PolicyBinding"/>), as the app saves them.</summary>
    public static TestVault Create() => new();

    /// <summary>The <c>llm</c> vault as saved before policy binding: the broker refuses its secrets until migrated.</summary>
    public static TestVault CreateUnbound() => new(bound: false);

    /// <summary>The same value and version, sealed again bound to <paramref name="policy"/>.</summary>
    SealedSecret Bind(SealedSecret secret, VaultDocument policy)
    {
        var dek = SecretEnvelope.UnwrapDek(secret, Tpm)!;
        var value = SecretEnvelope.Open(secret, dek)!;
        try
        {
            return SecretEnvelope.Seal(secret.Slug, secret.Version, value, [Tpm], PolicyBinding.Hash(policy, secret.Slug));
        }
        finally
        {
            Array.Clear(dek);
            Array.Clear(value);
        }
    }

    /// <summary>The <c>llm</c> vault plus whatever <paramref name="extra"/> seals with the stand-in TPM.</summary>
    public static TestVault CreateWith(Func<X25519KeyWrapper, (SealedSecret[] Secrets, Service[] Services)> extra) => new(extra);

    public static TestVault CreateWithSql() => new(tpm =>
    (
        [
            SecretEnvelope.Seal("appdb-read", 1, "Server=db.example;Database=AppDb;User ID=tiresias_provisioner;Password=p-read"u8, [tpm]),
            SecretEnvelope.Seal("appdb-write", 1, "Server=db.example;Database=AppDb;User ID=tiresias_provisioner;Password=p-write"u8, [tpm]),
        ],
        [
            new Service("appdb", new Uri("mssql://db.example/AppDb"),
            [
                new Grant("read", "appdb-read", new(new HashSet<string>(), []), IssuesLogins: true),
                new Grant("write", "appdb-write", new(new HashSet<string>(), [])),
            ]),
        ]
    ));

    /// <summary>Adds <c>ravendb</c> (https://a.raven.example), whose only grant, GET anything, presents <paramref name="pfx"/>.</summary>
    /// <param name="changes">The grant also opens WebSockets (the Changes API).</param>
    public static TestVault CreateWithRaven(byte[] pfx, bool changes = false) => new(tpm =>
    (
        [SecretEnvelope.Seal("raven-read", 1, System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(pfx)), [tpm])],
        [new Service("ravendb", new Uri("https://a.raven.example/"), [new Grant("read", "raven-read",
            changes ? new(new HashSet<string> { "GET", "WEBSOCKET" }, [VaultFile.Compile("^/")]) : Rule("GET", "^/"))])]
    ));

    /// <summary>Stands in for the approval root the Hello wrap derives.</summary>
    readonly byte[] approvalRoot = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

    /// <summary>The lease <see cref="SealTo"/> last sealed to, which the approval helpers sign for.</summary>
    public string? LeaseId { get; private set; }

    /// <summary>The raw public approval key for <paramref name="leaseId"/>, as <c>/lease/seal</c> carries it.</summary>
    public byte[] ApprovalKey(string leaseId)
    {
        using var key = Access.ApprovalKey.Derive(approvalRoot, leaseId);
        return Access.ApprovalKey.Public(key);
    }

    public Access.SignedApproval Approve(Access.Approval approval)
    {
        using var key = Access.ApprovalKey.Derive(approvalRoot, approval.LeaseId);
        return approval.Sign(key);
    }

    public Access.SignedApproval MintApproval(Access.AccessRequest request, DateTimeOffset? now = null) =>
        Approve(Access.Approval.ForMint(LeaseId!, request, now ?? DateTimeOffset.UtcNow));

    public Access.SignedApproval ElevateApproval(string service, string grant, TimeSpan duration, DateTimeOffset? now = null) =>
        Approve(Access.Approval.ForElevate(LeaseId!, service, grant, duration, "test", now ?? DateTimeOffset.UtcNow));

    public Access.SignedApproval TokenApproval(string service, DateTimeOffset? now = null) =>
        Approve(Access.Approval.ForToken(LeaseId!, service, "exec:test", "testing", now ?? DateTimeOffset.UtcNow));

    /// <summary>The <c>/lease/seal</c> body for <paramref name="offer"/>.</summary>
    public object SealBody(LeaseOffer offer) => new { offer.LeaseId, deks = SealTo(offer), approvalKey = ApprovalKey(offer.LeaseId) };

    public Dictionary<string, byte[]> SealTo(LeaseOffer offer)
    {
        LeaseId = offer.LeaseId;
        return Document.Secrets.ToDictionary(s => s.Slug, s => SealDek(offer, s.Slug, SecretEnvelope.UnwrapDek(s, Tpm)!));
    }

    /// <summary>Seals <paramref name="dek"/> to the lease for <paramref name="slug"/>, with this vault's approval key, and zeroes it.</summary>
    public byte[] SealDek(LeaseOffer offer, string slug, byte[] dek)
    {
        try
        {
            return SealedBox.Seal(offer.LeaseKey, dek, LeaseOffer.DekContext(offer.LeaseId, slug, ApprovalKey(offer.LeaseId)));
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    public void Dispose() => tpmKey.Dispose();

    static RequestRule Rule(string method, string allow) =>
        new(new HashSet<string> { method }, [VaultFile.Compile(allow)]);
}
