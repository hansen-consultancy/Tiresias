using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Tiresias.Broker;

namespace Tiresias.Tests;

/// <summary>
/// The broker's certificate loading against a real TLS handshake, which the fake nodes elsewhere
/// skip. On Windows, Schannel refuses a client key loaded with EphemeralKeySet; this is what
/// caught it.
/// </summary>
public class RavenTlsTests
{
    static byte[] SelfSigned(string name, string usage, bool dnsName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(usage)], false));
        if (dnsName)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");
            request.CertificateExtensions.Add(san.Build());
        }
        using var certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
        return certificate.Export(X509ContentType.Pfx);
    }

    [Test]
    public async Task A_certificate_from_the_vault_signs_in_over_real_tls()
    {
        using var serverCertificate = X509CertificateLoader.LoadPkcs12(SelfSigned("localhost", "1.3.6.1.5.5.7.3.1", dnsName: true), null);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, o => o.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.AllowAnyClientCertificate();
        })));
        await using var app = builder.Build();
        app.MapGet("/", (HttpContext c) => c.Connection.ClientCertificate?.Subject ?? "none");
        await app.StartAsync();
        var address = app.Urls.Single().Replace("127.0.0.1", "localhost", StringComparison.Ordinal);

        using var client = RavenClients.Load(SelfSigned("orders-app", "1.3.6.1.5.5.7.3.2", dnsName: false));
        var handler = (SocketsHttpHandler)RavenClients.DefaultHandler(client);
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) => certificate?.GetCertHashString() == serverCertificate.GetCertHashString();
        using var http = new HttpClient(handler);

        Assert.That(await http.GetStringAsync(address), Is.EqualTo("CN=orders-app"));
    }
}
