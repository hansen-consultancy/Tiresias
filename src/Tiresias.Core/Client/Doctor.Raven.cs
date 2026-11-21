using System.Globalization;
using System.Text.Json;

namespace Tiresias.Client;

/// <summary>A RavenDB service's client certificate as recorded when it was set up; the dates are <c>null</c> for one set up before Tiresias recorded them.</summary>
public sealed record DoctorRavenCertificate(string Service, string? Subject, string? Thumbprint, DateTimeOffset? NotAfter);

/// <summary>The broker's answer to <c>/clearance</c> as it came: its status and body.</summary>
public sealed record DoctorBrokerAnswer(int Status, byte[] Body);

/// <summary>What RavenDB says a service's certificate may do, asked through the broker with that certificate.</summary>
/// <param name="Level">RavenDB's security clearance: <c>ClusterAdmin</c>, <c>Operator</c> or <c>ValidUser</c>.</param>
/// <param name="Databases">The databases a <c>ValidUser</c> may use, with its access to each (<c>Read</c>, <c>ReadWrite</c>, <c>Admin</c>).</param>
public sealed record DoctorRavenClearance(string Level, IReadOnlyDictionary<string, string> Databases)
{
    /// <summary>The broker's <c>/clearance</c> answer, <c>{"clearance":…,"databases":{name:access}}</c>; <c>null</c> when it isn't one.</summary>
    public static DoctorRavenClearance? FromBroker(byte[] body)
    {
        try
        {
            using var json = JsonDocument.Parse(body);
            if (json.RootElement.ValueKind != JsonValueKind.Object
                || !json.RootElement.TryGetProperty("clearance", out var level) || level.ValueKind != JsonValueKind.String)
                return null;
            var databases = new SortedDictionary<string, string>(StringComparer.Ordinal);
            if (json.RootElement.TryGetProperty("databases", out var found) && found.ValueKind == JsonValueKind.Object)
                foreach (var database in found.EnumerateObject())
                    databases[database.Name] = database.Value.ValueKind == JsonValueKind.String ? database.Value.GetString()! : "";
            return new(level.GetString()!, databases);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

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

    /// <summary>
    /// Findings for RavenDB certificates cleared for more than one app needs: one that can change
    /// the server, a <c>ValidUser</c> for more than one database, or one with <c>Admin</c> on its database. Like expiry they carry no
    /// position. The certificate's thumbprint is in the name, so a replacement is a new finding.
    /// </summary>
    /// <param name="answers">Each certificate with the broker's answer, or <c>null</c> when it didn't answer or wasn't asked.</param>
    public static IEnumerable<DoctorCheck> RavenClearance(IEnumerable<(DoctorRavenCertificate Certificate, DoctorBrokerAnswer? Answer)> answers)
    {
        foreach (var (certificate, answer) in answers)
        {
            var name = certificate is { Subject: { } subject, Thumbprint: { } thumbprint }
                ? $"RavenDB clearance of {subject} for {certificate.Service} ({thumbprint[..Math.Min(8, thumbprint.Length)]})"
                : $"RavenDB clearance for {certificate.Service}";
            var service = certificate.Service;
            var clearance = answer is { Status: 200 } ? DoctorRavenClearance.FromBroker(answer.Body) : null;
            if (clearance is null)
            {
                yield return new(name, DoctorStatus.Ok, $"skipped: {Unanswered(answer)}");
                continue;
            }
            var databases = string.Join(", ", clearance.Databases.OrderBy(d => d.Key, StringComparer.Ordinal).Select(d => $"{d.Key} ({d.Value})"));
            if (clearance.Level is "ClusterAdmin" or "Operator")
                yield return new(name, DoctorStatus.Warn, $"{clearance.Level}: a program using {service} can change the server, not only read its data. Have RavenDB issue a certificate as ValidUser, limited to the app's databases, and replace it",
                    new ReplaceRavenCertificate(service), Kind: "RavenDB certificates that can change the server");
            else if (clearance.Databases.Count > 1)
                yield return new(name, DoctorStatus.Warn, $"ValidUser for {clearance.Databases.Count} databases: {databases}. A program using {service} reaches all of them; if the app needs fewer, have RavenDB issue a certificate limited to those, and replace it",
                    new ReplaceRavenCertificate(service), Kind: "RavenDB certificates for more than one database");
            else if (clearance.Databases.Any(d => d.Value == "Admin"))
                yield return new(name, DoctorStatus.Warn, $"ValidUser, Admin on {databases}: a program using {service} can change the database's indexes and settings, not only its documents. Have RavenDB issue a certificate with Read or ReadWrite, and replace it",
                    new ReplaceRavenCertificate(service), Kind: "RavenDB certificates with database Admin");
            else
                yield return new(name, DoctorStatus.Ok, clearance.Databases.Count == 1 ? $"{clearance.Level}, limited to {databases}" : $"{clearance.Level}, no databases");
        }
    }

    /// <summary>Why there's no clearance, from the broker's refusal code: the broker's own words, never a value.</summary>
    static string Unanswered(DoctorBrokerAnswer? answer)
    {
        if (answer is null)
            return "the broker didn't answer";
        string? reason = null;
        try
        {
            using var json = JsonDocument.Parse(answer.Body);
            if (json.RootElement.ValueKind == JsonValueKind.Object && json.RootElement.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String)
                reason = r.GetString();
        }
        catch (JsonException)
        {
        }
        return reason switch
        {
            "no-lease" => "locked; unlock the app to check",
            "elevation-required" => "the certificate's grant needs an elevation",
            "whoami-unanswered" => "RavenDB didn't answer the broker; check that the server's firewall allows this PC's address",
            "certificate-unreadable" => "the sealed certificate couldn't be opened; replace it",
            { } code => $"the broker refused ({code})",
            null => $"the broker answered {answer.Status}",
        };
    }
}

/// <summary>Replace a RavenDB service's sealed certificate with a new <c>.pfx</c>, in the app's Edit... on that service.</summary>
public sealed record ReplaceRavenCertificate(string Service) : DoctorFix
{
    public override string Instruction =>
        $"in the Tiresias app: Services, {Service}, Edit..., pick the new .pfx; have RavenDB issue it as ValidUser, limited to the app's databases";
}
