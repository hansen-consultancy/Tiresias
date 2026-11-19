using System.Globalization;

namespace Tiresias.Client;

/// <summary>A RavenDB service's client certificate as recorded when it was set up; the dates are <c>null</c> for one set up before Tiresias recorded them.</summary>
public sealed record DoctorRavenCertificate(string Service, string? Subject, string? Thumbprint, DateTimeOffset? NotAfter);

public static partial class Doctor
{
    /// <summary>How long before expiry a certificate is a finding.</summary>
    public static readonly TimeSpan ExpiryWarning = TimeSpan.FromDays(30);

    /// <summary>
    /// Findings for RavenDB client certificates that expired or will within <see cref="ExpiryWarning"/>.
    /// They don't move a delivery on either axis, so they are findings through their fix and carry no position.
    /// </summary>
    public static IEnumerable<DoctorCheck> RavenExpiry(IEnumerable<DoctorRavenCertificate> certificates, DateTimeOffset now)
    {
        foreach (var certificate in certificates)
        {
            if (certificate is not { NotAfter: { } notAfter, Subject: { } subject, Thumbprint: { } thumbprint })
            {
                yield return new($"RavenDB certificate for {certificate.Service}", DoctorStatus.Ok,
                    "expiry unknown: set up before Tiresias recorded it. Open the service in Services, Edit..., and save to record it");
                continue;
            }
            var name = $"RavenDB certificate {subject} for {certificate.Service} ({thumbprint[..Math.Min(8, thumbprint.Length)]})";
            var date = notAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            if (notAfter <= now)
                yield return new(name, DoctorStatus.Fail, $"expired on {date}, so every request through {certificate.Service} fails. Have RavenDB issue a new one, limited to the app's databases as ValidUser, and replace it",
                    new ReplaceRavenCertificate(certificate.Service), Kind: "RavenDB certificates that expired");
            else if (notAfter - now <= ExpiryWarning)
                yield return new(name, DoctorStatus.Warn, $"expires on {date}; requests through {certificate.Service} fail from then. Have RavenDB issue a new one, limited to the app's databases as ValidUser, and replace it",
                    new ReplaceRavenCertificate(certificate.Service), Kind: "RavenDB certificates expiring within 30 days");
        }
    }
}

/// <summary>Replace a RavenDB service's sealed certificate with a new <c>.pfx</c>, in the app's Edit... on that service.</summary>
public sealed record ReplaceRavenCertificate(string Service) : DoctorFix
{
    public override string Instruction =>
        $"in the Tiresias app: Services, {Service}, Edit..., pick the new .pfx; have RavenDB issue it as ValidUser, limited to the app's databases";
}
