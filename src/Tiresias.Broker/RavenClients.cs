using System.Security.Cryptography.X509Certificates;

namespace Tiresias.Broker;

/// <summary>Builds the handler that presents a RavenDB client certificate. A delegate so tests can stand in for the TLS stack.</summary>
public delegate HttpMessageHandler RavenHandlerFactory(X509Certificate2 certificate);

/// <summary>
/// One HTTP client per (lease, certificate secret), presenting the instance's client certificate.
/// The PFX is decrypted from the vault into memory only (<see cref="X509KeyStorageFlags.EphemeralKeySet"/>:
/// no key file, no key container) and the certificate and its connections are disposed when the
/// lease ends, so nothing of it outlives the lease.
/// </summary>
sealed class RavenClients(RavenHandlerFactory handlers) : IDisposable
{
    readonly Lock gate = new();
    readonly Dictionary<(string LeaseId, string SecretSlug), (X509Certificate2 Certificate, HttpMessageInvoker Client)> clients = [];

    /// <param name="takePfx">The secret, a base64 passwordless PFX; called only when there is no client for the lease yet.</param>
    public HttpMessageInvoker For(string leaseId, string secretSlug, Func<string> takePfx)
    {
        lock (gate)
        {
            if (clients.TryGetValue((leaseId, secretSlug), out var known))
                return known.Client;

            var pfx = Convert.FromBase64String(takePfx());
            X509Certificate2 certificate;
            try
            {
                certificate = X509CertificateLoader.LoadPkcs12(pfx, password: null, X509KeyStorageFlags.EphemeralKeySet);
            }
            finally
            {
                Array.Clear(pfx);
            }
            var client = new HttpMessageInvoker(handlers(certificate), disposeHandler: true);
            clients[(leaseId, secretSlug)] = (certificate, client);
            return client;
        }
    }

    public void EndLease(string leaseId)
    {
        lock (gate)
        {
            foreach (var key in clients.Keys.Where(k => k.LeaseId == leaseId).ToArray())
            {
                clients.Remove(key, out var ended);
                ended.Client.Dispose();
                ended.Certificate.Dispose();
            }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            foreach (var (certificate, client) in clients.Values)
            {
                client.Dispose();
                certificate.Dispose();
            }
            clients.Clear();
        }
    }

    public static HttpMessageHandler DefaultHandler(X509Certificate2 certificate) => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        SslOptions = { ClientCertificates = [certificate] },
    };
}
