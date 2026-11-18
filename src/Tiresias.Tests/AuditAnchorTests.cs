using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using AsicSharp.Models;
using AsicSharp.Services;
using Tiresias.Audit;
using Tiresias.Broker;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tiresias.Tests;

/// <summary>
/// A local TSA issuing real RFC 3161 tokens signed by a throwaway certificate, so the verification
/// path is the real one. <see cref="Imprint"/> overrides what it timestamps, to play a TSA that
/// answers for the wrong head.
/// </summary>
sealed class FakeTsa : ITsaClient, IDisposable
{
    readonly X509Certificate2 certificate;
    long serial;

    public FakeTsa()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Fake TSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], critical: true));
        // Valid from before the fixed Now below until long after today: a token signed at Now must verify on any later day.
        certificate = request.CreateSelfSigned(new DateTimeOffset(2026, 11, 16, 0, 0, 0, TimeSpan.Zero), DateTimeOffset.UtcNow.AddYears(10));
    }

    public DateTimeOffset Now { get; set; } = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);
    public byte[]? Imprint { get; set; }
    public Exception? Failure { get; set; }
    public int Requests { get; private set; }

    public byte[] Issue(byte[] hash)
    {
        var info = new Rfc3161TimestampTokenInfo(new Oid("1.3.6.1.4.1.99999.1"), new Oid("2.16.840.1.101.3.4.2.1"), hash,
            BitConverter.GetBytes(++serial), Now);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate) { IncludeOption = X509IncludeOption.EndCertOnly };

        // ESS signing-certificate-v2: RFC 3161 tokens name their signer, and .NET checks it.
        var ess = new AsnWriter(AsnEncodingRules.DER);
        using (ess.PushSequence())
        using (ess.PushSequence())
        using (ess.PushSequence())
            ess.WriteOctetString(SHA256.HashData(certificate.RawData));
        signer.SignedAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.16.2.47", ess.Encode()));

        var cms = new SignedCms(new ContentInfo(new Oid("1.2.840.113549.1.9.16.1.4"), info.Encode()));
        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    public Task<TimestampResult> RequestTimestampAsync(byte[] hash, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
    {
        Requests++;
        if (Failure is not null)
            throw Failure;
        return Task.FromResult(new TimestampResult { TokenBytes = Issue(Imprint ?? hash), Timestamp = Now });
    }

    public Task<TimestampResult> RequestTimestampForDataAsync(byte[] data, CancellationToken cancellationToken = default) =>
        RequestTimestampAsync(SHA256.HashData(data), HashAlgorithmName.SHA256, cancellationToken);

    public void Dispose() => certificate.Dispose();
}

public class AuditAnchorTests
{
    string dir = "";
    string path = "";
    AuditLog audit = null!;
    FakeTsa tsa = null!;
    ManualTime time = null!;
    AuditAnchoring anchoring = null!;

    [SetUp]
    public void SetUp()
    {
        dir = Directory.CreateTempSubdirectory("tir-anchor-").FullName;
        path = Path.Combine(dir, "audit.jsonl");
        time = new(new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero));
        audit = new AuditLog(path, time);
        tsa = new FakeTsa();
        anchoring = new AuditAnchoring(audit, tsa, time, NullLogger<AuditAnchoring>.Instance);
    }

    [TearDown]
    public void TearDown()
    {
        anchoring.Dispose();
        audit.Dispose();
        tsa.Dispose();
        TestDirectory.Delete(dir);
    }

    [Test]
    public async Task An_anchor_covers_every_line_before_it_and_keeps_the_chain_intact()
    {
        audit.Append(new(AuditKind.LeaseBegin, LeaseId: "l1"));
        audit.Append(new(AuditKind.LeaseEnd, LeaseId: "l1"));
        await anchoring.AnchorAsync();

        var check = AuditAnchors.Verify(path).Single();
        Assert.That(check.Error, Is.Null);
        Assert.That((check.Line, check.AnchoredLine), Is.EqualTo((3, 2)));
        Assert.That(check.Time, Is.EqualTo(tsa.Now));
        Assert.That(check.Signer, Is.EqualTo("CN=Fake TSA"));
        Assert.That(AuditLog.Verify(path), Is.Null);
    }

    [Test]
    public async Task The_TSA_sees_only_the_head_hash()
    {
        audit.Append(new(AuditKind.Allow, Consumer: "claude:secret-project", Path: "/v1/chat"));
        await anchoring.AnchorAsync();
        var anchor = JsonDocument.Parse(File.ReadLines(path).Last()).RootElement;
        Rfc3161TimestampToken.TryDecode(Convert.FromBase64String(anchor.GetProperty("evidence").GetString()!), out var token, out _);
        Assert.That(Convert.ToHexStringLower(token!.TokenInfo.GetMessageHash().Span), Is.EqualTo(anchor.GetProperty("prevHash").GetString()));
    }

    [Test]
    public async Task Nothing_new_since_the_last_anchor_asks_the_TSA_nothing()
    {
        await anchoring.AnchorAsync();
        Assert.That(tsa.Requests, Is.Zero, "empty log");

        audit.Append(new(AuditKind.LeaseBegin));
        await anchoring.AnchorAsync();
        await anchoring.AnchorAsync();
        Assert.That(tsa.Requests, Is.EqualTo(1));

        audit.Append(new(AuditKind.LeaseEnd));
        await anchoring.AnchorAsync();
        Assert.That(AuditAnchors.Verify(path).Select(c => c.AnchoredLine), Is.EqualTo(new int?[] { 1, 3 }));
    }

    [Test]
    public async Task A_token_for_another_head_is_not_appended()
    {
        audit.Append(new(AuditKind.LeaseBegin));
        tsa.Imprint = SHA256.HashData("something else"u8);
        await anchoring.AnchorAsync();
        Assert.That(AuditAnchors.Verify(path), Is.Empty);
        Assert.That(File.ReadLines(path).Count(), Is.EqualTo(1));
    }

    [Test]
    public async Task An_unreachable_TSA_costs_nothing_but_the_anchor_and_is_retried()
    {
        audit.Append(new(AuditKind.LeaseBegin));
        tsa.Failure = new HttpRequestException("no route");
        await anchoring.AnchorAsync();
        Assert.That(File.ReadLines(path).Count(), Is.EqualTo(1));
        audit.Append(new(AuditKind.Allow));

        tsa.Failure = null;
        await anchoring.AnchorAsync();
        Assert.That(AuditAnchors.Verify(path).Single().AnchoredLine, Is.EqualTo(2));
    }

    [Test]
    public void Check_refuses_garbage_a_wrong_head_and_a_tampered_signature()
    {
        var head = Convert.ToHexStringLower(SHA256.HashData("head"u8));
        var token = tsa.Issue(AuditAnchors.Imprint(head));
        Assert.That(AuditAnchors.Check(token, head).Error, Is.Null);
        Assert.That(AuditAnchors.Check([1, 2, 3], head).Error, Does.Contain("not an RFC 3161"));
        Assert.That(AuditAnchors.Check(token, new string('a', 64)).Error, Does.Contain("another head"));

        var signed = new SignedCms();
        signed.Decode(token);
        var signature = signed.SignerInfos[0].GetSignature();
        signature[^1] ^= 1;
        var tampered = (byte[])token.Clone();
        var at = tampered.AsSpan().IndexOf(signed.SignerInfos[0].GetSignature());
        signature.CopyTo(tampered, at);
        Assert.That(AuditAnchors.Check(tampered, head).Error, Is.Not.Null);
    }

    [Test]
    public void An_anchor_over_a_head_not_in_the_log_is_reported()
    {
        audit.Append(new(AuditKind.LeaseBegin));
        var foreign = Convert.ToBase64String(tsa.Issue(SHA256.HashData("another log"u8)));
        audit.Append(new(AuditKind.Anchor, Evidence: foreign));
        Assert.That(AuditAnchors.Verify(path).Single().Error, Does.Contain("no earlier head"));
    }

    [Test]
    public void The_broker_anchors_only_when_a_TSA_is_configured()
    {
        using var without = Host(null);
        Assert.That(without.Services.GetService<AuditAnchoring>(), Is.Null);

        using var with = Host("http://tsa.invalid");
        Assert.That(with.Services.GetService<AuditAnchoring>(), Is.Not.Null);
    }

    WebApplicationFactory<Program> Host(string? tsaUrl)
    {
        using var vault = TestVault.Create();
        var sub = Directory.CreateDirectory(Path.Combine(dir, tsaUrl is null ? "plain" : "tsa")).FullName;
        Vault.VaultFile.Save(Path.Combine(sub, "vault.json"), vault.Document);
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("Broker:VaultPath", Path.Combine(sub, "vault.json"));
            b.UseSetting("Broker:AuditPath", Path.Combine(sub, "audit.jsonl"));
            b.UseSetting("Broker:IdentityKeyPath", Path.Combine(sub, "identity.key"));
            if (tsaUrl is not null)
                b.UseSetting("Broker:TimestampAuthorityUrl", tsaUrl);
            b.ConfigureTestServices(s => s.AddSingleton<ITsaClient>(tsa));
        });
        factory.CreateClient().Dispose();
        return factory;
    }
}
