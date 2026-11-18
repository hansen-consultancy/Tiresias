using Tiresias.EnvironmentVariables;
using Tiresias.Policy;
using Tiresias.UserSecrets;

namespace Tiresias.Vault;

/// <summary>How a program reaches a service, which decides what the app tells someone to paste.</summary>
public enum ServiceUsageKind
{
    /// <summary>A user secrets connection string that becomes a temporary SQL login.</summary>
    SqlLogin,

    /// <summary>A user secrets RavenDB URL; the broker presents the client certificate.</summary>
    Raven,

    /// <summary>An environment variable holding a placeholder for the key, next to a base URL.</summary>
    Placeholder,
}

/// <param name="Snippet">What to paste, ready to copy.</param>
/// <param name="Write">The grant to use instead of <see cref="Snippet"/>'s for an app that saves data, if the service has one.</param>
public sealed record ServiceUsage(ServiceUsageKind Kind, string Snippet, string? Write = null);

/// <summary>
/// What a program needs to use a service: the same line the setup windows show when they save one,
/// so it can be shown again for any service later.
/// </summary>
public static class ServiceUsages
{
    /// <summary>Stands in for the database in a RavenDB snippet when the caller doesn't know it: the service doesn't name one.</summary>
    public const string AnyDatabase = "<database>";

    /// <param name="database">The RavenDB database the app uses, when known (just set up).</param>
    public static ServiceUsage For(Service service, string? database = null)
    {
        var logins = service.Grants.Where(g => g.IssuesLogins).ToArray();
        if (logins.Length > 0)
        {
            var read = logins.FirstOrDefault(g => g.Name == "read") ?? logins[0];
            var write = logins.FirstOrDefault(g => g.Name == "write" && g != read);
            return new(ServiceUsageKind.SqlLogin,
                $"\"ConnectionStrings:Default\": \"{new SecretReference(SecretReference.Sql, service.Slug, read.Name)}\"",
                write?.Name);
        }

        if (RavenSetupPlanner.Recognize(service) is not null)
            return new(ServiceUsageKind.Raven, $$"""
                "RavenDB": {
                  "Urls": [ "{{new SecretReference(SecretReference.Raven, service.Slug, null)}}" ],
                  "Database": "{{(string.IsNullOrWhiteSpace(database) ? AnyDatabase : database.Trim())}}"
                }
                """);

        var variable = service.Slug.Replace('-', '_').ToUpperInvariant() + "_API_KEY";
        return new(ServiceUsageKind.Placeholder,
            $"tir env placeholder add {variable} {service.Slug}   # base URL: {SealedEnvironment.BaseUrlVariableFor(variable)}");
    }
}
