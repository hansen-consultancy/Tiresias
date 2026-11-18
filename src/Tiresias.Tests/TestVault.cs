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

    TestVault(Func<X25519KeyWrapper, (SealedSecret[] Secrets, Service[] Services)>? extra = null)
    {
        Tpm = X25519KeyWrapper.ForKey("tpm", tpmKey);
        var (extraSecrets, extraServices) = extra?.Invoke(Tpm) ?? ([], []);
        Document = new(
            [
                SecretEnvelope.Seal("llm-read", 1, "Bearer sk-read"u8, [Tpm]),
                SecretEnvelope.Seal("llm-write", 1, "Bearer sk-write"u8, [Tpm]),
                SecretEnvelope.Seal("llm-admin", 1, "Bearer sk-admin"u8, [Tpm]),
                .. extraSecrets,
            ],
            [
                new Service("llm", new Uri("https://llm.example/"),
                [
                    new Grant("read", "llm-read", Rule("GET", "^/v1/models")),
                    new Grant("write", "llm-write", Rule("POST", "^/v1/")),
                    new Grant("admin", "llm-admin", Rule("DELETE", "^/v1/"), RequiresElevation: true),
                ]),
                .. extraServices,
            ]);
    }

    public X25519KeyWrapper Tpm { get; }
    public VaultDocument Document { get; }

    public static TestVault Create() => new();

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

    public Dictionary<string, byte[]> SealTo(LeaseOffer offer) =>
        Document.Secrets.ToDictionary(s => s.Slug, s =>
        {
            var dek = SecretEnvelope.UnwrapDek(s, Tpm)!;
            try
            {
                return SealedBox.Seal(offer.LeaseKey, dek, LeaseOffer.DekContext(offer.LeaseId, s.Slug));
            }
            finally
            {
                Array.Clear(dek);
            }
        });

    public void Dispose() => tpmKey.Dispose();

    static RequestRule Rule(string method, string allow) =>
        new(new HashSet<string> { method }, [VaultFile.Compile(allow)]);
}
