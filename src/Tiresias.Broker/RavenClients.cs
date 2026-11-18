using System.Security.Cryptography.X509Certificates;

namespace Tiresias.Broker;

/// <summary>Builds the handler that presents a RavenDB client certificate. A delegate so tests can stand in for the TLS stack.</summary>
public delegate HttpMessageHandler RavenHandlerFactory(X509Certificate2 certificate);

/// <summary>
/// One HTTP client per (lease, certificate secret), presenting the instance's client certificate.
/// The PFX is decrypted from the vault for the lease only (see <see cref="Load"/>), and the
/// certificate and its connections are disposed when the lease ends, which deletes its key. A Changes tunnel opened with the client watches
/// <see cref="Ending"/> and closes with it.
/// </summary>
sealed class RavenClients(RavenHandlerFactory handlers) : IDisposable
{
    readonly Lock gate = new();
    readonly Dictionary<(string LeaseId, string SecretSlug), (X509Certificate2 Certificate, HttpMessageInvoker Client)> clients = [];
    readonly Dictionary<string, CancellationTokenSource> leases = [];

    /// <summary>Cancelled when the lease ends (or the broker stops).</summary>
    public CancellationToken Ending(string leaseId)
    {
        lock (gate)
        {
            if (!leases.TryGetValue(leaseId, out var ending))
                leases[leaseId] = ending = new();
            return ending.Token;
        }
    }

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
                certificate = Load(pfx);
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
            if (leases.Remove(leaseId, out var ending))
            {
                ending.Cancel();
                ending.Dispose();
            }
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
            foreach (var ending in leases.Values)
            {
                ending.Cancel();
                ending.Dispose();
            }
            leases.Clear();
        }
    }

    /// <summary>
    /// Opens a PFX so Windows can present it as a TLS client certificate. Not
    /// <see cref="X509KeyStorageFlags.EphemeralKeySet"/>: Schannel refuses a key that exists only in
    /// memory ("The credentials supplied to the package were not recognized"). Instead the key goes
    /// to the user's key store, protected by DPAPI, until the certificate is disposed, which
    /// deletes it. Only a process that dies with the certificate open leaves the key file behind.
    /// </summary>
    /// <param name="exportable">The caller re-exports it (the app's setup seals it passwordless).</param>
    public static X509Certificate2 Load(byte[] pfx, string? password = null, bool exportable = false) =>
        X509CertificateLoader.LoadPkcs12(pfx, password, X509KeyStorageFlags.UserKeySet | (exportable ? X509KeyStorageFlags.Exportable : 0));

    public static HttpMessageHandler DefaultHandler(X509Certificate2 certificate) => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        SslOptions = { ClientCertificates = [certificate] },
    };
}
