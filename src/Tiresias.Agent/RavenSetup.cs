using System.Net;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Tiresias.Broker;
using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>The client certificate, as read from the PFX the user picked.</summary>
public sealed record RavenCertificateInfo(string Subject, string Thumbprint, DateTimeOffset NotAfter);

/// <summary>
/// Sets a RavenDB service up from the app: opens the PFX the user picked, asks the server for the
/// database's stats with it, the same way the broker will connect, then seals the certificate in
/// the vault (passwordless: the vault's envelope is what protects it) and saves the service. The
/// file and its password are used for this only; neither is kept.
/// </summary>
public static class RavenSetup
{
    /// <summary>Opens the PFX, so the app can say whose certificate it is before checking it.</summary>
    /// <exception cref="InvalidOperationException">Wrong password, not a PFX, or no private key; the message says which.</exception>
    public static RavenCertificateInfo Inspect(byte[] pfx, string? password)
    {
        using var certificate = Open(pfx, password);
        return Describe(certificate);
    }

    /// <param name="hello">The agent's open Windows Hello wrapper: the vault is sealed to it.</param>
    /// <exception cref="InvalidOperationException">A step failed; the message says what to do. Nothing is saved unless the server accepted the certificate.</exception>
    public static async Task<Service> RunAsync(RavenSetupPlan plan, byte[] pfx, string? password, HelloKeyWrapper hello,
        IProgress<string> progress, CancellationToken ct, RavenHandlerFactory? handlers = null)
    {
        var service = plan.Service ?? throw new InvalidOperationException("The plan has problems.");
        using var certificate = Open(pfx, password);

        progress.Report($"Asking {service.Upstream.Authority} for {plan.Database} with the certificate");
        await CheckAsync(service.Upstream, plan.Database, certificate, handlers ?? RavenClients.DefaultHandler, ct);

        progress.Report("Sealing the certificate in the vault");
        var passwordless = certificate.Export(X509ContentType.Pkcs12);
        var encoded = Encoding.ASCII.GetBytes(Convert.ToBase64String(passwordless));
        try
        {
            VaultEditor.SealSecret(plan.CertificateSecret, encoded, hello);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordless);
            CryptographicOperations.ZeroMemory(encoded);
        }
        VaultEditor.SetService(service);
        return service;
    }

    static X509Certificate2 Open(byte[] pfx, string? password)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = RavenClients.Load(pfx, string.IsNullOrEmpty(password) ? null : password, exportable: true);
        }
        catch (CryptographicException) when (!string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("The file didn't open with that password. Check the password, or that the file is the .pfx RavenDB gave you.");
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("The file didn't open. If it has a password, type it; otherwise check it is the .pfx RavenDB gave you, not a .crt or .key.");
        }
        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidOperationException("The file holds a certificate without its private key, so it can't sign in. Export the client certificate from RavenDB Studio again, as a .pfx.");
        }
        return certificate;
    }

    static RavenCertificateInfo Describe(X509Certificate2 certificate) =>
        new(certificate.GetNameInfo(X509NameType.SimpleName, false), certificate.Thumbprint, certificate.NotAfter);

    static async Task CheckAsync(Uri server, string database, X509Certificate2 certificate, RavenHandlerFactory handlers, CancellationToken ct)
    {
        var who = Describe(certificate);
        if (who.NotAfter < DateTimeOffset.Now)
            throw new InvalidOperationException($"The certificate {who.Subject} expired on {who.NotAfter:d}. Have RavenDB issue a new one.");

        using var client = new HttpClient(handlers(certificate)) { Timeout = TimeSpan.FromSeconds(15) };
        var url = new Uri(server, $"/databases/{Uri.EscapeDataString(database)}/stats");
        HttpResponseMessage response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            response = await client.SendAsync(request, ct);
        }
        catch (HttpRequestException e) when (e.InnerException is AuthenticationException tls)
        {
            throw new InvalidOperationException($"The TLS connection to {server.Authority} failed: {Innermost(tls).Message}", e);
        }
        catch (HttpRequestException e)
        {
            throw new InvalidOperationException($"Couldn't reach {server.Authority}: {e.Message}", e);
        }
        catch (TaskCanceledException e) when (!ct.IsCancellationRequested)
        {
            throw new InvalidOperationException($"{server.Authority} didn't answer within 15 seconds.", e);
        }

        using (response)
        {
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    return;
                // RavenDB answers 403 both for a certificate it doesn't know and for one without
                // access to this database; only its message tells them apart.
                case HttpStatusCode.Unauthorized:
                case HttpStatusCode.Forbidden when (await response.Content.ReadAsStringAsync(ct)).Contains("unknown", StringComparison.OrdinalIgnoreCase):
                    throw new InvalidOperationException($"{server.Authority} doesn't know the certificate {who.Subject} ({who.Thumbprint}). Register it in RavenDB Studio (Manage Server, Certificates), then try again.");
                case HttpStatusCode.Forbidden:
                    throw new InvalidOperationException($"The certificate {who.Subject} has no access to {database}. Give it access in RavenDB Studio (Manage Server, Certificates, Edit), then try again.");
                case HttpStatusCode.NotFound or HttpStatusCode.ServiceUnavailable when await MentionsDatabaseAsync(response, ct):
                    throw new InvalidOperationException($"{server.Authority} has no database {database}, or it is offline. Check the name; RavenDB database names are as shown in Studio.");
                default:
                    throw new InvalidOperationException($"{server.Authority} answered {(int)response.StatusCode} {response.ReasonPhrase} for {database}'s stats.");
            }
        }
    }

    /// <summary>TLS failures nest: "see inner exception" twice before the reason Windows gave.</summary>
    static Exception Innermost(Exception e)
    {
        while (e.InnerException is { } inner)
            e = inner;
        return e;
    }

    static async Task<bool> MentionsDatabaseAsync(HttpResponseMessage response, CancellationToken ct) =>
        response.StatusCode == HttpStatusCode.NotFound
        || (await response.Content.ReadAsStringAsync(ct)).Contains("Database", StringComparison.OrdinalIgnoreCase);
}
